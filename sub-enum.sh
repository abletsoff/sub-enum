#!/usr/bin/bash

domain_regex="(_?([a-z0-9-]){1,61}\.)+[a-z0-9]{1,61}"
user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"

f_transparency () {
	json_data=$(curl -A "$user_agent" "https://crt.sh/?q={$domain}&output=json" 2>/dev/null)
	
	# Retrieving CN certificate field 
	common_names=$(echo $json_data | grep -P -o "\"common_name\":\"${domain_regex}\"" | \
		cut -d '"' -f 4 | sort -u)
	
	# Retrieving SAN certificate field
	subject_alt_names=$(echo $json_data | grep -P -o '"name_value":"(\w|\.|-|\*|\\n)*"' | \
		cut -d '"' -f 4 | sed 's/\\n/\n/g' | sort -u)
		
	sum_names=("${common_names[@]}" "${subject_alt_names[@]}")
	subs=($(for sub in "${sum_names[@]}"; \
       		do echo "${sub}"; done | sort -u))

	f_output "ctr.sh" "${subs[@]}" 
}

f_spf () {
	record=$(dig TXT +short $domain | grep -P '^"v=spf1')
	subs=$(echo $record | grep -o -P "(a|include):\S*|redirect=\S*" \
		| cut -d ":" -f2 | cut -d "=" -f2 | cut -d '"' -f1| sort -u)
	f_output "SPF" "${subs[@]}"	
}

f_mx () {
	record=$(dig MX +short $domain)
	subs=$(echo "$record" | grep -o -P "\d \S*." |  cut -d " " -f2 | sed "s/.$//g")
	f_output "mx" "${subs[@]}"	
}

f_dmarc () {
	record=$(dig TXT +short "_dmarc.${domain}")
	subs=$(echo "$record" | grep -o -P "@${domain_regex}" | sed "s/@//g" \
		| sort -u | uniq)
	f_output "DMARC" "${subs[@]}"	

}
f_google () {
	user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
	url_allowed="[A-z,0-9,\/,\-,_,\.,~,&,=,\?,:]"
	html=$(curl -k -A "${user_agent}" \
		"https://www.google.com/search?q=site:*.${domain}+-inurl:www.${domain}"`
		`"${keyword_operator}&num=100" 2>/dev/null)
	subs=$(echo $html | grep -o -P "https?:\/\/[a-z,0-9,\.,\-]*${domain}" \
		| sed "s/ /\n/g" | cut -d "/" -f3 | sort -u)
	f_output "Google" "${subs[@]}"	
}

f_zone_transfer () {
	nameservers=($(dig NS +short ${domain}))
       	for nameserver in ${nameservers[@]}; do	
		axfr_response=$(dig AXFR ${domain} @${nameserver})
		subs=$(echo "$axfr_response" | grep -o -P "${domain_regex}" \
		| grep ${domain} | sort -u | uniq)
		f_output "Zone transfer" "${subs[@]}"
	done
}

f_ptr_lookup () {
	ip_addresses=("$@")
	for ip in ${ip_addresses[@]}; do
		record=$(dig +short -x $ip | sed "s/\.$//g")
		subs=(${subs[@]} "$record")
	done
	f_output "PTR lookup" "${subs[@]}"
}

f_csp () {
	printed_subs=("$@")
	for sub in ${printed_subs[@]}; do
		csp_header=$(curl -A "$user_agent" -s -D - -o /dev/null -k -L ${sub} | \
			grep --ignore-case "^Content-Security-Policy: ")
		csp_domains=$(echo $csp_header | grep --color -o -P "${domain_regex}")
		subs=(${subs[@]} "${csp_domains[@]}")
	done
	f_output "CSP" "${subs[@]}"
}

f_print_help () {
	echo -e "Usage: sub-enum [options...] <domain>\n" \
		"-h\tdisplay this help and exit\n" \
		"-e\tE-mail DNS entries (MX, SPF, DMARC)\n" \
		"-g\tGoogle search\n" \
		"-t\tCertificate transparancy check (crt.sh)\n" \
		"-z\tZone transfering\n" \
		"-p\tPTR lookup\n" \
		"-c\tContent-Security-Policy analyzing\n" \
		"-O\tMarkdown output\n" \
		"-X\tExclude uresolved domains\n" \
		"-T\tTruncated output"
}

f_output () {
	description=$1
	shift 
	subs=("$@")
		
	for sub in ${subs[@]}; do
		# Domain address resolving
		#===Need to handle CNAME resolve troubles===
		resolve=$(dig +short "$sub")
		if [[ $resolve = '' ]]; then
			resolve="unresolved"
		else
			for resolved_ip in ${resolve[@]}; do
				duplicate="false"
				for ip in ${ip_addresses[@]}; do
					if [[ "$ip" == "$resolved_ip" ]]; then
						duplicate="true"
						break
					fi
				done
				if [[ "$duplicate" == "false" ]]; then
					ip_addresses=(${ip_addresses[@]} "$resolved_ip")
				fi
			done
		fi

		resolve=$(echo "$resolve" | sed -z "s/\n/, /g" | sed "s/, $//g")

		# Avoiding duplicate entries
		duplicate="false"
		for p_sub in ${printed_subdomains[@]}; do
			if [[ "$sub" = "$p_sub" ]]; then
				duplicate="true"
				break
			fi
		done
		if [[ $duplicate = "true" ]]; then
			continue
		else	
			printed_subdomains=(${printed_subdomains[@]} "$sub")
		fi

		# Process related domains
		if [[ "$sub" != *"$domain"* ]]; then
			related=(${related[@]} "$sub")
			continue
		fi
		
		# Output
		if [[ $resolve = "unresolved" ]] && [[ $exclude_uresolved = "true" ]]; then
			continue
		fi
		if [[ $truncated_output = "true" ]]; then
			echo $sub

		else
			if [[ $markdown_output = "true" ]]; then

				echo "|$sub|$resolve|$description|"
			else
				echo "$sub - $resolve - $description"
			fi
		fi
	done
}

while getopts "hegtzpcOXT" opt; do
	case $opt in
		e)	email_check="true"
			check="true";;
		g)	google_check="true"
			check="true";;
		t)	transparency_check="true"
			check="true";;
		z)	zone_transfer="true"
			check="true";;
		p)	ptr_lookup="true";;
		c)	csp="true"
			check="true";;
		O)	markdown_output="true";;
		X)	exclude_uresolved="true";;
		T)	truncated_output="true";;
		h) 	f_print_help
			exit;;
		?) 	exit;;
	esac
done
shift $((OPTIND-1))

domain=$1

if [[ $domain != "" ]]; then
	if [[ $markdown_output = "true" ]]; then
		echo "|Domain|Resolve|Source|"
		echo "|:---:|:---:|:---:|"
	fi
	subs=($domain)
	f_output "Domain" ${domain[@]}
	if [[ $email_check = "true" ]]; then
		f_mx
		f_spf
		f_dmarc
	fi
	if [[ $google_check = "true" ]]; then
		f_google
	fi
	if [[ $transparency_check = "true" ]]; then
		f_transparency
	fi
	if [[ $zone_transfer = "true" ]]; then
		f_zone_transfer
	fi
	if [[ $csp = "true" ]]; then
		f_csp "${printed_subdomains[@]}"
	fi
	if [[ $ptr_lookup = "true" ]]; then
		f_ptr_lookup "${ip_addresses[@]}"
	fi
	if [[ $check != "true" ]]; then
		f_mx
		f_spf
		f_dmarc
		f_google
		f_transparency
		f_zone_transfer
		f_ptr_lookup "${ip_addresses[@]}"
	fi

	if (( ${#related[@]} )); then
		echo -ne "\nRelated domains:"
		for r_domain in ${related[@]}; do
			echo -n " $r_domain;"
		done
		echo ""
	fi

else
	f_print_help
fi

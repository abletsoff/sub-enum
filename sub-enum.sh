#!/usr/bin/bash

domain_regex="(\w|\.|-|\*)*"

f_transparency () {
	json_data=$(curl "https://crt.sh/?q={$domain}&output=json" 2>/dev/null)
	
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
		subs=$(echo "$axfr_response" | grep -o -P "${domain_regex}${domain}" \
		| sort -u | uniq)
		f_output "Zone transfer" "${subs[@]}"
	done
}

f_print_help () {
	echo -e "Usage: sub-enum [options...] <domain>\n" \
		"-h\tdisplay this help and exit\n" \
		"-e\tE-mail DNS entries (MX, SPF, DMARC)\n" \
		"-g\tGoogle search\n" \
		"-t\tCertificate transparancy check (crt.sh)\n" \
		"-z\tZone transfering\n" \
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
		resolve=$(dig $sub +short | sed -z "s/\n/, /g" | sed "s/, $//g")
		if [[ $resolve = '' ]]; then
			resolve="unresolved"
		fi

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

while getopts "hegtzOXT" opt; do
	case $opt in
		e)	email_check="true"
			check="true";;
		g)	google_check="true"
			check="true";;
		t)	transparency_check="true"
			check="true";;
		z)	zone_transfer="true"
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
	if [[ $check != "true" ]]; then
		f_mx
		f_spf
		f_dmarc
		f_google
		f_transparency
		f_zone_transfer
	fi

	if (( ${#related[@]} )); then
		echo -ne "\nRelated domains:"
		for r_domain in ${related[@]}; do
			echo -n " $r_domain;"
		done
		echo
	fi
else
	f_print_help
fi

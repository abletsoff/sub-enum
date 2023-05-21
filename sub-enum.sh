#!/usr/bin/bash

f_transparency () {
	unset subs
	json_data=$(curl "https://crt.sh/?q={$domain}&output=json" 2>/dev/null)
	
	# Retrieving CN certificate field 
	common_names=$(echo $json_data | grep -P -o '"common_name":"(\w|\.|-|\*)*"' | \
		cut -d '"' -f 4 | sort -u)
	
	# Retrieving SAN certificate field
	subject_alt_names=$(echo $json_data | grep -P -o '"name_value":"(\w|\.|-|\*|\\)*"' | \
		cut -d '"' -f 4 | sed 's/\\n/\n/g' | sort -u)
		
	tmp_names=("${common_names[@]}" "${subject_alt_names[@]}")
	transparency_subs=($(for sub in "${tmp_names[@]}"; \
       		do echo "${sub}"; done | sort -u))

	for sub in ${transparency_subs[@]}; do
		if [ "$sub" != "$domain" ] && [ "$sub" != "*.$domain" ]; then
			f_related_decision $sub
		fi
	done
	f_output "ctr.sh" "${subs[@]}" 
}

f_spf () {
	unset subs
	spf_record=$(dig TXT +short $domain | grep -P '^"v=spf1')
	spf_subs=$(echo $spf_record | grep -o -P "(a|include):\S*|redirect=\S*" \
		| cut -d ":" -f2 | cut -d "=" -f2 | cut -d '"' -f1| sort -u)

	for sub in ${spf_subs[@]}; do
		if [ "$sub" != "$domain" ]; then
			f_related_decision $sub
		fi
	done
	f_output "SPF" "${subs[@]}"	
}

f_mx () {
	unset subs
	mx_record="$(dig MX +short $domain)"
	mx_subs=$(echo $mx_record | grep -o -P "\d \S*." |  cut -d " " -f2 | sed "s/.$//g")
	for sub in ${mx_subs[@]}; do
		f_related_decision $sub
	done
	f_output "MX" "${subs[@]}"	
}

f_google () {
	unset subs
	user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
	url_allowed="[A-z,0-9,\/,\-,_,\.,~,&,=,\?,:]"
	html=$(curl -k -A "${user_agent}" \
		"https://www.google.com/search?q=site:*.${domain}+-inurl:www.${domain}"`
		`"${keyword_operator}&num=100" 2>/dev/null)
	google_subs=$(echo $html | grep -o -P "https?:\/\/[a-z,0-9,\.,\-]*${domain}" \
		| sed "s/ /\n/g" | cut -d "/" -f3 | sort -u)
	for sub in "${google_subs[@]}"; do
		subs=(${subs[@]} "$sub")
	done
	f_output "Google" "${subs[@]}"	
}

f_zone_transfer () {
	unset subs
	nameservers=($(dig NS +short ${domain}))
       	for nameserver in ${nameservers[@]}; do	
		output=$(dig AXFR ${domain} @${nameserver})
		echo $output
	done
}

f_print_help () {
	echo -e "Usage: sub-enum [options...] <domain>\n" \
		"-h\tdisplay this help and exit\n" \
		"-m\tMX entry analyzing\n" \
		"-s\tSPF entry analyzing\n" \
		"-g\tGoogle search\n" \
		"-t\tCertificate transparancy check (crt.sh)\n" \
		"-z\tZone transfering\n" \
		"-O\tMarkdown output\n" \
		"-X\tExclude uresolved domains\n" \
		"-T\tTruncated output"
}

f_related_decision () {
	sub=$1
	if [[ "$sub" == *"$domain"* ]]; then
		subs=(${subs[@]} "$sub")
	else
		related=(${related[@]} "$sub")
	fi
}

f_output () {
	description=$1
	shift 
	subdomains=("$@")

	for sub in ${subdomains[@]}; do

		# Domain address resolving
		resolve=$(dig $sub +short | sed -z "s/\n/, /g" | sed "s/, $//g")
		if [[ $resolve = '' ]]; then
			resolve="unresolved"
		fi

		# Avoiding duplicate entries
		duplicate="false"
		for p_sub in ${printed_subdomains[@]}; do
			if [[ $sub = $p_sub ]]; then
				duplicate="true"
				break
			fi
		done
	
		if [[ $duplicate = "true" ]]; then
			continue
		else	
			printed_subdomains=(${printed_subdomains[@]} "$sub")
		fi
		
		# Output
		if [[ $resolve = "unresolved" ]] && [[ $exclude_uresolved = "true" ]]; then
			continue
		fi
		if [[ $truncated_output = "true" ]]; then
			sub=$(echo $sub | sed "s/\.$domain$//g")
		fi	
		if [[ $markdown_output = "true" ]]; then

			echo "|$sub|$resolve|$description|"
		else
			echo "$sub - $resolve"
		fi
	done
}

while getopts "hmsgtzOXT" opt; do
	case $opt in
		m)	mx_check="true"
			check="true";;
		s)	spf_check="true"
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
	if [[ $mx_check = "true" ]]; then
		f_mx
	fi
	if [[ $spf_check = "true" ]]; then
		f_spf
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
		f_google
		f_transparency
		f_zone_transfer
	fi

	f_output "Related" "${related[@]}" 
else
	f_print_help
fi

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
	mx_record="$(dig MX +short $domain)"
	mx_subs=$(echo $mx_record | grep -o -P "\d \S*." |  cut -d " " -f2 | sed "s/.$//g")
	for sub in ${mx_subs[@]}; do
		f_related_decision $sub
	done
	f_output "MX" "${subs[@]}"	

	
}

f_google () {
	# site:*.example.com -inurl:www.example.com
}

f_print_help () {
	echo -e "Usage: sub-enum [options...] <domain>\n" \
		"-h\tdisplay this help and exit\n" \
		"-m\tMX entry analyzing\n" \
		"-s\tSPF entry analyzing\n" \
		"-t\tCertificate transparancy check (crt.sh)\n" \
		"-O\tMarkdown output\n" \
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
		if [[ $truncated_output = "true" ]]; then
			sub=$(echo $sub | sed "s/\.$domain$//g")
		fi	
		if [[ $markdown_output = "true" ]]; then

			echo "|$resolve|$sub|$description|"
		else
			echo "$sub - $resolve"
		fi
	done
}

while getopts "hmstOT" opt; do
	case $opt in
		m)	mx_check="true"
			check="true";;
		s)	spf_check="true"
			check="true";;
		t)	transparency_check="true"
			check="true";;
		O)	markdown_output="true";;
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
		echo "|Resolve|Domain|Source|"
		echo "|---|---|---|"
	fi
	if [[ $mx_check = "true" ]]; then
		f_mx
	fi
	if [[ $spf_check = "true" ]]; then
		f_spf
	fi
	if [[ $transparency_check = "true" ]]; then
		f_transparency
	fi
	if [[ $check != "true" ]]; then
		f_mx
		f_spf
		f_transparency
	fi

	f_output "Related" "${related[@]}" 
else
	f_print_help
fi

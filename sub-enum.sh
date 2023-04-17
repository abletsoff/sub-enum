#!/usr/bin/bash

f_transparency () {
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

	echo "--- Certificate transparency ---"	
	for sub in ${transparency_subs[@]}; do
		if [ "$sub" != "$domain" ] && [ "$sub" != "*.$domain" ]; then
		       	if [[ "$sub" == *"$domain"* ]]; then
				echo $sub
			else
				related=(${related[@]} "$sub")
			fi
		fi
	done
}

f_spf () {
	spf_record=$(dig TXT +short $domain | grep -P '^"v=spf1')
	spf_a=$(echo $spf_record | grep -o "a:\S*" | cut -d ":" -f2)
	
	# include:
	# redirect:
	# ip4: (PTR enumeration)

	echo "--- SPF ---"	
	for sub in $spf_a; do
		if [ "$sub" != "$domain" ]; then
			echo $sub
		fi
	done
}

f_tmp_related () {
	echo "--- Related ---"
	for sub in ${related[@]}; do
		echo $sub
	done

}

f_print_help () {
	echo -e "Usage: sub-enum [options...] <domain>\n" \
			 "-h\tdisplay this help and exit\n" \
			 "-s\tSPF entry analyzing\n" \
			 "-t\tCertificate transparancy check (crt.sh)\n"
			 "-o\tMarkdown output"
}

f_output () {
	

}

while getopts "hst" opt; do
	case $opt in
		s)	spf_check="true";;
		t)	transparency_check="true";;
		o)	markdown_output="true";;
		h) 	f_print_help
			exit;;
		?) 	exit;;
	esac
done
shift $((OPTIND-1))

domain=$1

if [[ $domain != "" ]]; then
	if [[ $spf_check = "true" ]]; then
		f_spf
	fi
	if [[ $transparency_check = "true" ]]; then
		f_transparency
	fi
	f_tmp_related
else
	f_print_help
fi

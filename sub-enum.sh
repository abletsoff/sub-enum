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
        
    subs=("${common_names[@]}" "${subject_alt_names[@]}")

    f_parsing "ctr.sh" "${subs[@]}" 
}

f_spf () {
    record=$(dig TXT +short $domain | grep -P '^"v=spf1')
    subs=$(echo $record | grep -o -P "(a|include):\S*|redirect=\S*" \
        | cut -d ":" -f2 | cut -d "=" -f2 | cut -d '"' -f1)
    f_parsing "SPF" "${subs[@]}"    
}

f_mx () {
    record=$(dig MX +short $domain)
    subs=$(echo "$record" | grep -o -P "\d \S*." |  cut -d " " -f2 | sed "s/.$//g")
    f_parsing "mx" "${subs[@]}"    
}

f_dmarc () {
    record=$(dig TXT +short "_dmarc.${domain}")
    subs=$(echo "$record" | grep -o -P "@${domain_regex}" | sed "s/@//g")
    f_parsing "DMARC" "${subs[@]}"    

}

f_google () {
    user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
    url_allowed="[A-z,0-9,\/,\-,_,\.,~,&,=,\?,:]"
    html=$(curl -k -A "${user_agent}" \
        "https://www.google.com/search?q=site:*.${domain}+-inurl:www.${domain}"`
        `"${keyword_operator}&num=100" 2>/dev/null)
    subs=$(echo $html | grep -o -P "https?:\/\/[a-z,0-9,\.,\-]*${domain}" \
        | sed "s/ /\n/g" | cut -d "/" -f3)
    f_parsing "Google" "${subs[@]}"    
}

f_zone_transfer () {
    nameservers=($(dig NS +short ${domain}))
           for nameserver in ${nameservers[@]}; do    
        axfr_response=$(dig AXFR ${domain} @${nameserver})
        subs=$(echo "$axfr_response" | grep -o -P "${domain_regex}" \
        | grep ${domain})
        f_parsing "Zone transfer" "${subs[@]}"
    done
}

f_ptr_lookup () {
    ip_addresses=("$@")
    for ip in ${ip_addresses[@]}; do
        record=$(dig +short -x $ip | sed "s/\.$//g")
        subs=(${subs[@]} "$record")
    done
    f_parsing "PTR lookup" "${subs[@]}"
}

f_web () {
    printed_subs=("$@")
    for sub in ${printed_subs[@]}; do
        response=$(curl -A "$user_agent" -s -k -L -D - --connect-timeout 2 ${sub})
        csp_header=$( echo "$response" | grep --ignore-case "^Content-Security-Policy: ")
        csp_domains=$(echo $csp_header | grep --color -o -P "${domain_regex}")
        csp_subs=(${csp_subs[@]} "${csp_domains[@]}")
        html_domains=$(echo $response | grep -o -P "${domain_regex}" | grep "$domain")
        html_subs=(${html_subs[@]} "${html_domains[@]}")
    done

    f_parsing "CSP" "${csp_subs[@]}"
    f_parsing "HTML" "${html_subs[@]}"
}

f_ip_parsing () {
    for resolve in ${ip_addresses[@]}; do
        whois=$(whois -B $resolve)
        inetnum=$(echo "$whois" | grep -P "^inetnum:" | grep -P -o "\d.*$")
        netname=$(echo "$whois" | grep -P "^netname:" | cut -d ":" -f2 \
            | grep -P -o "\S*$")
        country=$(echo "$whois" | grep -P "^country:" | cut -d ":" -f2 \
                   | grep -P -o "\S*$" | head -n 1)
	whois_data=$(f_output "false" "$inetnum" "$netname" "$country")

        duplicate=""
        for ip_range in "${ip_ranges[@]}"; do
            if [[ "$ip_range" == "$whois_data" ]]; then
                duplicate="true"
                break
            fi
        done
        
        if [[ $duplicate == "" ]]; then
            ip_ranges=("${ip_ranges[@]}" "$whois_data")
        fi
    done
    
    f_output "true" "Inetnum" "Netname" "Country"
    for ip_range in "${ip_ranges[@]}"; do
        echo $ip_range
    done
}

f_print_help () {
    echo -e "Usage: sub-enum [options...] <domain>\n" \
        "-h\tdisplay this help and exit\n" \
        "-e\tE-mail DNS entries (MX, SPF, DMARC)\n" \
        "-g\tGoogle search\n" \
        "-t\tCertificate transparancy check (crt.sh)\n" \
        "-z\tZone transfering\n" \
        "-p\tPTR lookup\n" \
        "-w\tHTTP headers and HTML page source analyzing\n" \
        "-O\tMarkdown output\n" \
        "-X\tExclude uresolved domains"
}

f_resolve () {
    sub=$1
    resolve=$(dig +short "$sub")

    if [[ $resolve = '' ]]; then
        resolve="unresolved"
    else
        for resolved_ip in ${resolve[@]}; do
            duplicate=""
            
            for ip in ${ip_addresses[@]}; do
                if [[ "$ip" == "$resolved_ip" ]]; then
                    duplicate="true"
                    break
                fi
            done

            if [[ "$duplicate" == "" && "$related_domain" == "" ]]; then
                ip_check=$(echo $resolved_ip \
                       | grep -o -P "([1-2]?\d{1,2}\.){3}[1-2]?\d{1,2}")

                if [[ $ip_check == "" ]]; then
                    cname_subs=(${cname_subs[@]} \
                        $(echo $resolved_ip | sed 's/\.$//g'))
                else
                    ip_addresses=(${ip_addresses[@]} "$resolved_ip")
                fi
            fi
        done

        resolve=$(echo "$resolve" | sed -z "s/\n/, /g" | sed "s/, $//g")
    fi
}

f_parsing () {
    description=$1
    shift 
    unsorted_subs=("$@")
    subs=($(for sub in "${unsorted_subs[@]}"; \
               do echo "${sub}"; done | sort -u))
        
    for sub in ${subs[@]}; do
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

        if [[ "$sub" != *"$domain"* ]]; then
            related_domain='true'
        fi
        
        f_resolve $sub

        # Output
        if [[ $resolve = "unresolved" ]] && [[ $exclude_uresolved = "true" ]]; then
            continue
        fi

	output=$(f_output "false" "$sub" "$resolve" "$description")

        if [[ $related_domain == '' ]]; then
            echo "$output"
        else
            related_output=("${related_output[@]}" "$output")
            related_domain=''
        fi
    done
}

f_related_parsing () {
    if (( ${#related_output[@]} )); then
	f_output "true" "Related" "Resolve" "Source"
        for r_output in "${related_output[@]}"; do
            echo "$r_output"
        done
    fi
}

f_output () {
    is_title=$1
    shift 
    row=("$@")   

    if [[ $is_title == "true" && ${row[0]} != "Subdomain" ]]; then
        echo ""
    fi
	
    if [[ $markdown_output = "true" ]]; then
        for element in "${row[@]}"; do
            echo -n "|${element}"
        done
        echo "|"

        if [[ $is_title == "true" ]]; then
            for element in "${row[@]}"; do
                echo -n "|:---:"
            done
            echo "|"
        fi
    else
        if [[ $is_title == "true" ]]; then
            echo "${row[0]}:"
        else
            for element in "${row[@]}"; do
                if [[ "${row[0]}" == "$element" ]]; then
                    echo -n "$element"
                else
                    echo -n " - $element"
                fi
            done
            echo ""
        fi
    fi

}

while getopts "hegtzpwOXT" opt; do
    case $opt in
        e)    email_check="true"
            check="true";;
        g)    google_check="true"
            check="true";;
        t)    transparency_check="true"
            check="true";;
        z)    zone_transfer="true"
            check="true";;
        p)    ptr_lookup="true";;
        w)    web="true"
            check="true";;
        O)    markdown_output="true";;
        X)    exclude_uresolved="true";;
        h)     f_print_help
            exit;;
        ?)     exit;;
    esac
done
shift $((OPTIND-1))

domain=$1

if [[ $domain != "" ]]; then
    f_output "true" "Subdomain" "Resolve" "Source"
    subs=($domain)
    f_parsing "Domain" ${domain[@]}
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
    if [[ $web = "true" ]]; then
        f_web "${printed_subdomains[@]}"
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
        f_web "${printed_subdomains[@]}"
        f_ptr_lookup "${ip_addresses[@]}"
    fi
    
    f_parsing "CNAME" "${cname_subs[@]}"
    f_ip_parsing
    f_related_parsing

else
    f_print_help
fi

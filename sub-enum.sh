#!/usr/bin/bash

domain_regex="(_?([a-z0-9-]){1,61}\.)+[a-z0-9]{1,61}"
user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"

f_transparency () {
    f_status "Requesting crt.sh (subdomains)"
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
    f_status "SPF record"
    record=$(dig TXT +short $domain | grep -P '^"v=spf1')
    subs=$(echo $record | grep -o -P "(a|include):\S*|redirect=\S*" \
        | cut -d ":" -f2 | cut -d "=" -f2 | cut -d '"' -f1)
    f_parsing "SPF" "${subs[@]}"    
}

f_mx () {
    f_status "MX record"
    record=$(dig MX +short $domain)
    subs=$(echo "$record" | grep -o -P "\d \S*." |  cut -d " " -f2 | sed "s/.$//g")
    f_parsing "mx" "${subs[@]}"    
}

f_dmarc () {
    f_status "DMARC record"
    record=$(dig TXT +short "_dmarc.${domain}")
    subs=$(echo "$record" | grep -o -P "@${domain_regex}" | sed "s/@//g")
    f_parsing "DMARC" "${subs[@]}"    

}

f_google () {
    dorks=("site:*.${domain}+-inurl:www.${domain}", "site:*.*.${domain}"
        "site:*.*.*.${domain}")
    unset subs

    for dork in ${dorks[@]}; do
        f_status "Google dork: $dork"
        google_page_start=0
        while true; do
            # By default parse only first 300 searches
            if (($google_page_start >= 300)); then
                break
            fi
            
            html=$(curl -k -A "${user_agent}" \
                "https://www.google.com/search?q=${dork}&num=100&start=${google_page_start}" \
                2>/dev/null)
           
            # Generate warning when Google detect unusual traffic
            google_block=$(echo $html | grep -P "https:\/\/www.google.com\/sorry\/index\?")
            if [[ $google_block != '' ]]; then
                warning="true"
                break
            fi

            extracted_subs=$(echo $html | grep -o -P "https?:\/\/[a-z,0-9,\.,\-]*${domain}" \
                | sed "s/ /\n/g" | cut -d "/" -f3)

            subs=(${subs[@]} ${extracted_subs[@]})
            
            # Check if there are more search pages to parse
            extracted_subs_count=$(echo "$extracted_subs" | wc -l)
            if (( $extracted_subs_count >= 100 )); then
                google_page_start=$(($google_page_start + $extracted_subs_count))
            else
                break
            fi

            # Myabe Google will be less suspicious if we sleep for one seccond
            sleep 1 
        done
    done

    f_parsing "Google" "${subs[@]}"    
}

f_zone_transfer () {
    f_status "Requesting DNS zone transfer"
    nameservers=($(dig NS +short ${domain}))
    for nameserver in ${nameservers[@]}; do    
        axfr_response=$(dig AXFR ${domain} @${nameserver})
        subs=$(echo "$axfr_response" | grep -o -P "${domain_regex}" \
        | grep ${domain})
        f_parsing "Zone transfer" "${subs[@]}"
    done
}

f_ptr_lookup () {
    f_status "PTR lookup"
    ip_addresses=("$@")
    for ip in ${ip_addresses[@]}; do
        record=$(dig +short -x $ip | sed "s/\.$//g")
        subs=(${subs[@]} "$record")
    done
    f_parsing "PTR lookup" "${subs[@]}"
}

f_web () {
    printed_subs=("$@")
    f_status "HTTP & HTML scraping  "
        
    # First redirect: HTTP -> HTTPS
    # Second redirect: example.com -> www.example.com
    response=$(for printed_sub in ${printed_subs[@]}; do echo $printed_sub; done \
        | xargs -P10 -I SUB curl -A "$user_agent" -i -s -k -L -D - --max-time 2 \
        --max-redirs 2 SUB -v 2>&1 | tr '\0' '\n')
    requested_subs=(${requested_subs[@]} ${printed_subs[@]})
    location_headers=$(echo "$response" | grep --ignore-case "^Location: ")
    redirect_domains=$(echo "$location_headers" \
        | grep -o -P "https?:\/\/${domain_regex}" | cut -d "/" -f3)
    redirect_subs=(${redirect_subs[@]} ${redirect_domains[@]})

    csp_header=$( echo "$response" | grep --ignore-case "^Content-Security-Policy: ")
    csp_domains=$(echo "$csp_header" | grep -o -P "${domain_regex}")
    csp_subs=(${csp_subs[@]} ${csp_domains[@]})

    html_domains=$(echo "$response" | grep -o -P "${html_domain_regex}")
    html_subs=(${html_subs[@]} ${html_domains[@]})

    # Data parsing for f_crt_reverse (placed outside of f_crt_reverse for optimization)
    certificate_org=$(echo "$response" | grep -P "^\*  subject" \
        | grep -o "O=[^;]*" | cut -d "=" -f2)
    certificate_orgs=("${certificate_orgs[@]}" "$certificate_org")
    
    # It is not optimal to place output here but it will improve output dynamic    
    f_parsing "CSP" "${csp_subs[@]}"
    f_parsing "HTML" "${html_subs[@]}"
    f_parsing "HTTP Redirect" "${redirect_subs[@]}"

    # Recursive search
    discovered_subs=($(echo "${html_subs[@]} ${csp_subs[@]} ${redirect_subs[@]}" \
        | sed "s/ /\n/g" | sort | uniq | grep -P "${domain}$"))
    
    not_requested_subs=()

    for discovered_sub in ${discovered_subs[@]}; do
        duplicate="False"
        for requested_sub in ${requested_subs[@]}; do
            if [[ "$discovered_sub" == "$requested_sub" ]]; then
                duplicate="True"
                break
            fi
        done
        if [[ $duplicate = "False" ]]; then
            not_requested_subs=("${not_requested_subs[@]}" "$discovered_sub")
        fi
    done
    
    if [ ${#not_requested_subs[@]} -ne 0 ]; then 
        f_web "${not_requested_subs[@]}"
    fi
}

f_crt_reverse () {
    f_status "Requesting crt.sh (certificate subject)"
    array=("$@")

    # Excluding duplicates
    readarray -t array <<< $(for element in "${array[@]}"; do echo "$element"; done | sort -u)
    for element in "${array[@]}"; do
        url=$(echo "https://crt.sh/?q=${element}&output=json" | sed "s/ /+/g")
        json_data=$(curl -A "$user_agent" "$url" -s)
        partial_common_names=($(echo "$json_data" | grep -P -o '"common_name":"[^,]*"' \
            | cut -d ':' -f2 | sed 's/"//g'))
        common_names=(${common_names[@]} ${partial_common_names[@]})
    done
    f_parsing "Reverse certificate" "${common_names[@]}"
}

f_web_archive () {
    f_status "Web archive request"
    subs=$(curl -s \
        "http://web.archive.org/cdx/search/cdx?url=*.${domain}/*&collapse=urlkey&fl=original" \
        | grep -P -o "$html_domain_regex" | sort -u)
    f_parsing "Web archive" "${subs[@]}"
}

f_hackertarget () {
    f_status "Hackertarget request"
    response=$(curl -s "https://api.hackertarget.com/hostsearch/?q=${domain}")
    if [[ $(echo "$response" | grep "API ") != '' ]]; then
        warning="true"
        hackertarget_block="true"
    elif [[ $(echo "$response" | grep "error ") != '' ]]; then
        true
    else
        subs=$(echo "$response" | cut -d ',' -f1)
        f_parsing "Hackertarget" "${subs[@]}"
    fi
}
f_api_key () {
    resource=$1
    api_key=$(cat /usr/share/api-keys.txt 2> /dev/null | grep $resource | cut -d ':' -f2)
    
    # Search in current directory 
    if [[ $api_key = '' ]]; then
        api_key=$(cat api-keys.txt 2> /dev/null | grep "$resource" | cut -d ':' -f2)
    fi

    if [[ $api_key = '' ]]; then
        warrning="true"
        api_file_troubles="true"
    fi
    
    echo $api_key

}
f_securitytrails () {
    f_status "SecurityTrails"
    api_key=$(f_api_key "SecurityTrails")
    response=$(curl -s "https://api.securitytrails.com/v1/domain/${domain}"`
        `"/subdomains?chilren_only=flase" -H "apikey: $api_key")

    raw_subdomains=$(echo $response | grep -P -o '\[.*\]' | sed 's/,//g' \
        | sed 's/\[//g' | sed 's/\]//g')
    for raw_subdomain in ${raw_subdomains[@]}; do
        sub="$(echo $raw_subdomain | sed 's/"//g').$domain"
        subs=(${subs[@]} $sub)
    done
    
    f_parsing "SecurityTrails" "${subs[@]}"

    #TODO:add warning about API limit exceeding
}

f_ip_parsing () {
    for resolve in ${ip_addresses[@]}; do
        f_status "WHOIS lookup for $resolve"
        whois=$(whois $resolve)
        inetnum=$(echo "$whois" | grep -P -i "^NetRange:|^inetnum:" | grep -P -o "\d.*$")
        netname=$(echo "$whois" | grep -P -i "^NetName:" | cut -d ":" -f2 \
            | grep -P -o "\S*$")
        country=$(echo "$whois" | grep -P -i "^Country:" | cut -d ":" -f2 \
                   | grep -P -o "\S*$" | head -n 1)
	whois_data=$(f_output "false" "false" "$inetnum" "$netname" "$country")

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
    
    f_output "true" "true" "Inetnum" "Netname" "Country"
    for ip_range in "${ip_ranges[@]}"; do
        echo $ip_range
    done
}

f_print_help () {
    echo -e "Usage: sub-enum [options...] <domain>\n" \
        "-h\tdisplay this help and exit\n" \
        "-e\tE-mail DNS entries (MX, SPF, DMARC)\n" \
        "-g\tGoogle search\n" \
        "-t\tCertificate transparancy subdomains (crt.sh)\n" \
        "-c\tCertificate transparancy reverse search\n" \
        "-z\tZone transfering\n" \
        "-p\tPTR lookup\n" \
        "-w\tHTTP headers and HTML page source analyzing\n" \
        "-W\tWeb archive\n" \
        "-a\tUse public APIs (explicit)\n" \
        "-O\tMarkdown output\n" \
        "-L\tLimit DNS resolve output"
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
        if [[ "$limit_resolve_output" == "true" ]]; then
            resolve=$(echo "$resolve" | sed 's/\.$//g' | head -n 1)
        else
            resolve=$(echo "$resolve" | sed -z "s/\n/, /g" | sed "s/, $//g")
        fi
    fi
}

f_parsing () {
    description=$1
    shift 
    unsorted_subs=("$@")

    f_status "DNS resolving"
    subs=($(for sub in "${unsorted_subs[@]}"; \
               do echo "${sub}"; done | sort -u))
        
    for sub in ${subs[@]}; do
        # Avoiding duplicate entries
        duplicate="false"
        for p_sub in ${discovered_domains[@]}; do
            if [[ "$sub" == "$p_sub" ]]; then
                duplicate="true"
                break
            fi
        done

        if [[ $duplicate = "true" ]]; then
            continue
        else    
            discovered_domains=(${discovered_domains[@]} "$sub")
        fi

        if [[ "$sub" != *"$domain"* ]] && [[ "$cidr" == '' ]]; then
            related_domain='true'
        fi
        
        f_resolve $sub

        # Output
	    output=$(f_output "false" "false" "$sub" "$resolve" "$description")

        if [[ $related_domain != '' ]]; then
            related_output=("${related_output[@]}" "$output")
            related_domain=''
        elif [[ $resolve = "unresolved" ]]; then
            unresolved_output=("${unresolved_output[@]}" "$output")
        else
            effective_subdomains=(${effective_subdomains[@]} "$sub")
	        f_output "false" "true" "$sub" "$resolve" "$description"
        fi
    done
}

f_related_parsing () {
    if (( ${#related_output[@]} )); then
	f_output "true" "true" "Related" "Resolve" "Source"
        for r_output in "${related_output[@]}"; do
            echo "$r_output"
        done
    fi
}

f_unresolved_parsing () {
    if (( ${#unresolved_output[@]} )); then
	f_output "true" "true" "Unresolved" "Resolve" "Source"
        for r_output in "${unresolved_output[@]}"; do
            echo "$r_output"
        done
    fi
}

f_output () {
    is_title=$1
    actual_print=$2

    if [[ $actual_print == "true" ]]; then
        if [[ $last_printed_status == "true" ]]; then
            echo -en "\e[1A\e[K\e[1A" 
        fi
        last_printed_status="false"
    fi

    shift 2

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

f_status () {
    message=$1
    
    # [1A - move  cursor up to 1 line
    # [K - Erase to end of line

    if [[ $last_printed_status == "true" ]]; then
        echo -e "\e[1A\e[K\e[1A\nStatus: ${message}"
    else
        echo -e "\nStatus: ${message}"
    fi

    last_printed_status="true"
}

f_statistic () {
	f_output "true" "true" "Statistic" "Value"

    subdomains_count="${#effective_subdomains[@]}"
    f_output "false" "true" "active domains" "$subdomains_count"

    ip_blocks_count="${#ip_ranges[@]}"
    f_output "false" "true" "internet blocks" "$ip_blocks_count"
    f_output "false" "true" "start date" "$start_date"
    f_output "false" "true" "stop date" "$(date)"

}

f_ip_input_parsing () {
    base=$(echo "$cidr" | cut -d "/" -f1) 
    mask=$(echo "$cidr" | cut -d "/" -f2)
    if [[ $mask == $base ]]; then
        echo $base
    else
        IFS=. read -r i1 i2 i3 i4 <<< "$base"
        ip=$((i1 * 256 ** 3 + i2 * 256 ** 2 + i3 * 256 + i4))
        range=$((2 ** (32-mask)))
        
        for ((i=0; i<range; i++)); do
            ip=$((ip+1))
            octet4=$((ip % 256))
            octet3=$(((ip / 256) % 256))
            octet2=$(((ip / 256 / 256) % 256))
            octet1=$(((ip / 256 / 256 / 256) % 256))
            echo "$octet1.$octet2.$octet3.$octet4"
        done
    fi
}

start_date=$(date)

while getopts "hegtczpwWaOL" opt; do
    case $opt in
        e)  email_check="true"
            check="true";;
        g)  google_check="true"
            check="true";;
        t)  transparency_check="true"
            check="true";;
        c)  crt_reverse_check="true"
            web_check="true"
            check="true";;
        z)  zone_transfer_check="true"
            check="true";;
        p)  ptr_lookup_check="true";;
        w)  web_check="true"
            check="true";;
        W)  web_archive_check="true"
            check="true";;
        a)  apis_check="true";;
        O)  markdown_output="true";;
        L)  limit_resolve_output="true";;
        h)  f_print_help
            exit;;
        ?)  exit;;
    esac
done
shift $((OPTIND-1))

domain=$1
if [[ $domain == "" ]]; then
    f_print_help
    exit 1
fi

html_domain_regex="(_?([a-z0-9-]){1,61}\.)+${domain}" # Performance considerations

if [[ $(echo $domain | grep -P "(?:[0-9]{1,3}\.){3}[0-9]{1,3}") != '' ]]; then
    ip_input="True"
    cidr="$domain"
fi

if [[ $ip_input != "True" ]]; then
    f_output "true" "true" "Subdomain" "Resolve" "Source"
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
    if [[ $zone_transfer_check = "true" ]]; then
        f_zone_transfer
    fi
    if [[ $web_archive_check = "true" ]]; then
        f_web_archive
    fi
    if [[ $web_check = "true" ]]; then
        f_web "${effective_subdomains[@]}"
    fi
    if [[ $crt_reverse_check = "true" ]]; then
        f_crt_reverse "${certificate_orgs[@]}"
    fi
    if [[ $ptr_lookup_check = "true" ]]; then
        f_ptr_lookup "${ip_addresses[@]}"
    fi
    if [[ $check != "true" ]]; then
        f_mx
        f_spf
        f_dmarc
        f_google
        f_transparency
        f_zone_transfer
        f_web_archive
        if [[ $apis_check = "true" ]]; then
            f_hackertarget
            f_securitytrails
        fi
        f_web "${effective_subdomains[@]}"
        f_crt_reverse "${certificate_orgs[@]}"
        f_ptr_lookup "${ip_addresses[@]}"
    fi
    
    f_parsing "CNAME" "${cname_subs[@]}"
    f_unresolved_parsing
    f_ip_parsing
    f_related_parsing

    if [[ $warning == 'true' ]]; then
        echo -e "\nWarnings:"

        if [[ $google_block != '' ]]; then
            echo "Google have detected unusual traffic." 
        elif [[ $hackertarget_block != '' ]]; then
            echo "Hackertarget API count exceeded." 
        elif [[ $api_file_troubles != '' ]]; then
            echo "There is problems with API file" 
        fi
    fi
    
    f_statistic
else
    f_output "true" "true" "Domain" "Resolve" "Source"
    ip_list=($(f_ip_input_parsing))
    f_ptr_lookup "${ip_list[@]}"
    f_web ${ip_list[@]}
    f_web "${effective_subdomains[@]}"
    f_unresolved_parsing
    f_ip_parsing
fi

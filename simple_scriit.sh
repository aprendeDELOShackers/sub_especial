#!/bin/bash
host=$1
wordlists=/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
resolvers=/home/josema96/HackerOne/program_bash/Recon_sub/resolvers.txtt
				#enum sub
subs(){
for domain in $(cat $host);do
	mkdir -p $domain $domain/Sub $domain/pure_dns $domain/httpx $domain/nuclei $domain/wayback $domain/gf $domain/unfurl $domain/masscan
	#amass enum -d -passive $domain | anew $domain/Sub/sub.txt
	#assetfinder $domain -sub-only | anew  $domain/Sub/sub.txt
	#findomain -t $domain | anew >> $domain/Sub/sub.txt
	subfinder -d $domain | anew  $domain/Sub/sub.txt
	#puredns bruteforce $wordlists $domain -r $resolvers -w >> $domain/Sub/sub.txt
done
}
subs
				#resol domain o dns
#rsol_dns(){
#for domain in $(cat $host);do
#	puredns resolve $domain/Sub/sub.txt -r $resolvers | anew $domain/pure_dns/sub_vali.txt
#done
#}
#rsol_dns
				#lookinf for http/https domain
url_probe(){
for domain in $(cat $host);do
	cat $domain/pure_dns/sub_vali.txt | httpx -silent -status-code -title -content-type -o $domain/httpx/url_vali.txt
done
}
url_probe
				#scan http/https results "nuclei"
scanner(){
for domain in $(cat $host);do
	cat $domain/httpx/url_vali.txt | nuclei -t /root/nuclei-templates/cves/ -c 50 -o $domain/nuclei/cves.txt
	cat $domain/httpx/url_vali.txt | nuclei -t /root/nuclei-templates/vulnerabilities/ -c 50 -o $domain/nuclei/vulnerabilities.txt
        cat $domain/httpx/url_vali.txt | nuclei -t /root/nuclei-templates/technologies/ -c 50 -o $domain/nuclei/technologies.txt
        cat $domain/httpx/url_vali.txt | nuclei -t /root/nuclei-templates/file/ -c 50 -o $domain/nuclei/file.txt
done
}
scanner
				#fetch data
wayback_data(){
for domain in $(cat $host);do
	cat $domain/pure_dns/sub_vali.txt | waybackurls | tee $domain/wayback/way1.txt
	cat $domain/wayback/way1.txt | egrep -v "(\.jpg|\.jpeg|\.git|\.css|\.tif|\.tiff|\.png|\.ttf|\.wolf|\.wolf2|\.ico|\.pdf|\.svg|\.txt|\.html)" | sed 's/:80//g;s/:443//g' | anew > $domain/wayback/way_valido.txt
	rm $domain/wayback/way1.txt
done
}
wayback_data
			#filter "valid" urls from wayback data
#fuzzer(){
#for domain in $(cat $host);do
#	ffuf -c -u "FUZZ" -w $domain/wayback/way_valido.txt -f csv  -o $domain/wayback/fuzzer1.txt
#	cat $domain/wayback/fuzzer1.txt | grep "http" | awk -f "," 'print $1' >> $domain/wayback/fuzz_valid.txt
#	rm $domain/wayback/fuzzer1.txt
#done
#}
#fuzzer
				#filter results with "gf"
gf_patterns(){
for domain in $(cat $host);do
	gf xss $domain/wayback/way_valido.txt | tee $domain/wayback/gf/xss.txt
	gf sqli $domain/wayback/way_valido.txt | tee $domain/wayback/gf/sqli.txt
	gf ssrf $domain/wayback/way_valido.txt | tee $domain/wayback/gf/ssrf.txt
	gf idor $domain/wayback/way_valido.txt | tee $domain/wayback/gf/idor.txt
	gf lfi $domain/wayback/way_valido.txt | tee $domain/wayback/gf/lfi.txt
	gf json-sec $domain/wayback/way_valido.txt | tee $domain/wayback/gf/json-sec.txt
done
}
gf_patterns

			#genere_dict (unfurl=paths/parameters) de way
wordlist_custom(){
for host in $(cat $domain);do
	cat $domain/wayback/way_valido.txt | unfurl -unique paths > $domain/unfurl/pahts.txt
	cat $domain/wayback/way_valido.txt | unfurl -unique keys > $domain/unfurl/keys.txt
done
}
wordlist_custom

			#domain to IP (resolve)
get_ip(){
for host in $(cat $domain);do
	cat $domain/Rsol_dns/sub_vali.txt massdns -r $resolvers -t A -o S -w $domain/masscan/resul.txt
	gf ip $domain/masscan/resul.txt | anew > $domain/masscan/ip.txt
done
}
get_ip

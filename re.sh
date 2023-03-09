#!/bin/bash
host=$1
wordlists=/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
resolvers=/home/josema96/HackerOne/program_bash/Recon_sub/resolvers.txtt
				#enum sub
subs(){
for domain in $(cat $host);do
	mkdir -p $domain $domain/Sub $domain/pure_dns $domain/fhc $domain/nuclei $domain/wayback $domain/gf $domain/unfurl $domain/masscan
	#amass enum -d -passive $host | anew $host/Sub/sub.txt
	#assetfinder $host -sub-only | anew  $host/Sub/sub.txt
	#findomain -t $host | anew >> $host/Sub/sub.txt
	subfinder -d $domain | anew  $domain/Sub/sub.txt
	#puredns bruteforce $wordlists $host -r $resolvers -w >> $host/Sub/sub.txt
done
}
subs
				#resol domain o dns
#rsol_dns(){
#for host in $(cat $host);do
#	puredns resolve $host/Sub/sub.txt -r $resolvers | anew $host/pure_dns/sub_vali.txt
#done
#}
#rsol_dns
				#lookinf for http/https domain
fhc_probe(){
for domain in $(cat $host);do
	cat $domain/Sub/sub.txt | fhc | anew $domain/fhc/url_vali.txt
done
}
fhc_probe
				#scan http/https results "nuclei"
#scanner(){
#for host in $(cat $host);do
#	cat $host/urlprobe/url_vali.txt | nuclei -t /root/nuclei-templates/cves/ -c 50 -o $host/nuclei/cves.txt
#	cat $host/urlprobe/url_vali.txt | nuclei -t /root/nuclei-templates/vulnerabilities/ -c 50 -o $host/nuclei/vulnerabilities.txt
 #       cat $host/urlprobe/url_vali.txt | nuclei -t /root/nuclei-templates/technologies/ -c 50 -o $host/nuclei/technologies.txt
  #      cat $host/urlprobe/url_vali.txt | nuclei -t /root/nuclei-templates/file/ -c 50 -o $host/nuclei/file.txt
#done
#}
#scanner
				#fetch data
#wayback_data(){
#for host in $(cat $host);do
#	cat $host/Sub/sub.txt | waybackurls | tee $host/wayback/way1.txt
#	cat $host/wayback/way1.txt | egrep -v "(\.jpg|\.jpeg|\.git|\.css|\.tif|\.tiff|\.png|\.ttf|\.wolf|\.wolf2|\.ico|\.pdf|\.svg|\.txt|\.html)" | sed 's/:80//g;s/:443//g' | anew > $host/wayback/way_valido.txt
#	rm $host/wayback/way1.txt
#done
#}
#wayback_data
				#filter "valid" urls from wayback data
#fuzzer(){
#for host in $(cat $host);do
#	ffuf -c -u "FUZZ" -w $host/wayback/way_valido.txt -f csv  -o $host/wayback/fuzzer1.txt
#	cat $host/wayback/fuzzer1.txt | grep "http" | awk -f "," 'print $1' >> $host/wayback/fuzz_valid.txt
#	rm $host/wayback/fuzzer1.txt
#done
#}
#fuzzer
				#filter results with "gf"
#gf_patterns(){
#for host in $(cat $host);do
#	gf xss $host/wayback/way_valido.txt | tee $host/wayback/gf/xss.txt
#	gf sqli $host/wayback/way_valido.txt | tee $host/wayback/gf/sqli.txt
#	gf ssrf $host/wayback/way_valido.txt | tee $host/wayback/gf/ssrf.txt
#	gf idor $host/wayback/way_valido.txt | tee $host/wayback/gf/idor.txt
#	gf lfi $host/wayback/way_valido.txt | tee $host/wayback/gf/lfi.txt
#	gf json-sec $host/wayback/way_valido.txt | tee $host/wayback/gf/json-sec.txt
#done
#}
#gf_patterns

			#genere_dict (unfurl=paths/parameters) de way
#wordlist_custom(){
#for host in $(cat $host);do
#	cat $host/wayback/way_valido.txt | unfurl -unique paths > $host/unfurl/pahts.txt
#	cat $host/wayback/way_valido.txt | unfurl -unique keys > $host/unfurl/keys.txt
#done
#}
#wordlist_custom

			#domain to IP (resolve)
#get_ip(){
#for host in $(cat $host);do
#	cat $host/Rsol_dns/sub_vali.txt massdns -r $resolvers -t A -o S -w $host/masscan/resul.txt
#	gf ip $host/masscan/resul.txt | anew > $host/masscan/ip.txt
#done
#}
#get_ip

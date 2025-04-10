for i in {1..10}
do
  python3 vpn_tester.py configs${i}.txt -o output${i}.txt --singbox-path /usr/local/bin/sing-box
done

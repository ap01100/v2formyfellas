for i in {1..10}
do
  python3 url_test.py configs${i}.txt -o output${i}.txt --singbox-path /usr/local/bin/sing-box
done

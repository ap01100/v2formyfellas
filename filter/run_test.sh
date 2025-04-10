for i in {1..10}
do
  python3 url_test.py input/configs${i}.txt -ao output/output${i}.txt -w 5 --singbox-path /usr/local/bin/sing-box
done

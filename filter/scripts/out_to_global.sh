cat ../output1.txt > ../../configs.txt
for i in {2..10}
do
  cat ../output${i}.txt >> ../../configs.txt
done

cat ../output/output1.txt > ../../configs.txt
for i in {2..10}
do
  cat ../output/output${i}.txt >> ../../configs.txt
done

cipher='' #<![CDATA[xxxxx]]>中的密文xxx
password_mask_array=[19,78,10,15,100,213,43,23]
password=''
cipher=cipher[3:]
for i in range(int(len(cipher))/4):
    c1=int("0x"+cipher[i*4:(i+1)*4],16)
    c2=c1^password_mask_array[i%8]
    password=password+chr(c2)
print(password)

#https://blog.csdn.net/huangyongkang666/article/details/128762993?spm=1001.2101.3001.6661.1&utm_medium=distribute.pc_relevant_t0.none-task-blog-2%7Edefault%7ECTRLIST%7ERate-1-128762993-blog-103682982.pc_relevant_default&depth_1-utm_source=distribute.pc_relevant_t0.none-task-blog-2%7Edefault%7ECTRLIST%7ERate-1-128762993-blog-103682982.pc_relevant_default&utm_relevant_index=1
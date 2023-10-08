import pandas as pd


with open("sub_1.txt") as f:
    # print(len(f.readlines()))
    # lines = [l.strip().split() for l in f if len(l.split())==7]
    lines = f.readlines()
    
lines = [[int(i) for i in line.split()] for line in lines if len(line.split())==7]
print("Number of lines in the file:", len(lines))


min_list = lines[0]
max_list = lines[0]

print(min_list)
print(max_list)
print()

for line in lines:
    min_list = [min(min_list[index], line[index]) for index in range(len(min_list))]
    max_list = [max(max_list[index], line[index]) for index in range(len(max_list))]

print(min_list)
print(max_list)




# df = pd.read_excel("excel/sub.xlsx")

# minlist = [0, 0, 0, 0, 0, 0]
# maxlist = [0, 0, 0, 0, 0, 0]

# for index, row in df.iterrows():
#     min = [min(minlist[i], row[i+1]) for i in range(6)]
#     max = [max(maxlist[i], row[i+1]) for i in range(6)]



# print(df.columns)

# min_list = lines[0]
# max_list = lines[0]

# for line in lines:
#     min_list = [min(min_list[index], line[index]) for index in range(len(min_list))]
#     max_list = [max(max_list[index], line[index]) for index in range(len(max_list))]

# print(min_list)
# print(max_list)



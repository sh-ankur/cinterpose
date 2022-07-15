#### Interposing library to analyze access pattern of applications.

##### Building the project
```
make
```

##### Test sample app
```
make test
```

##### Build the database project
```
cd ref/resource
wget http://infosys.uni-saarland.de/teaching/tables.tar.xz
tar xvf tables.tar.xz
head -n 1000000 lineitem.tbl > lineitem1kk.tbl
cd ..
mkdir build_release
cd build_release
cmake -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ..
ninja
cd ..
```

##### Execute the sample test
```
mkdir lib
cp -a ../lib/interpose.so lib/
LD_PRELOAD=./lib/interpose.so build_release/bin/benchmark_indices 1000000 resource/lineitem_1kk.tbl resource/orders.tbl 3 43
```

### README

`git clone https://github.com/encryptogroup/ABY.git`

`cd ABY/`

`mkdir build && cd build`

`cmake ..`

`make`

`cd ../../`

`cp ABY FHEoracle/`

`cd FHEoracle`

`make`

./client_test -r 0

./server_test -r1
docker build -t my_hotbpf_image .
docker run -it --name my_hotbpf_container -v $(pwd)/../:/home/hotbpf/ my_hotbpf_image

docker start my_hotbpf_container
docker exec -it my_hotbpf_container /bin/bash


docker stop my_hotbpf_container
docker rm my_hotbpf_container
docker rmi my_hotbpf_image


cd /home/hotbpf/analyzer/build/lib

/home/hotbpf/analyzer/build/lib/analyzer -struct msg_msg `find /home/hotbpf/linux-5.15.106/ipc -name "*.bc"`

/home/hotbpf/analyzer/build/lib/analyzer -struct hci_conn `find /home/hotbpf/linux-5.15.106/net/bluetooth/ -name "*.bc"`
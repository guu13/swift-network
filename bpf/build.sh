go generate ./cgroup_connect4/
go generate ./cgroup_getpeername4/
go generate ./cgroup_sendmsg4/

go build

sudo ./bpf

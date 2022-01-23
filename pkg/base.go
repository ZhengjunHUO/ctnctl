package pkg

import (
	"os/exec"
	_ "embed"
)

const (
	//bpfProgName	= "./pkg/bpf.o"

	egressFuncName  = "egress_filter"
	ingressFuncName = "ingress_filter"

	egressMapName   = "egress_blacklist"
	ingressMapName  = "ingress_blacklist"
	egressL4MapName   = "egress_l4_blacklist"
	ingressL4MapName  = "ingress_l4_blacklist"
	flowMapName	= "data_flow"

	bpfPath		= "/sys/fs/bpf/"
)

var (
	allLinks	= []string{"/cgroup_egs_link", "/cgroup_igs_link"}
	allMaps		= []string{"/dataflow_map", "/egs_map", "/igs_map", "/egs_l4_map", "/igs_l4_map"}
)

//go:embed bpf.o
var bpfProgBytes []byte

// Return container's fullid and cgroup path
//   eg. /sys/fs/cgroup/system.slice/docker-5b81537a967793cf5c8b562bd5b9cb6b55045ed339ed328390f70d466aa84134.scope
func GetContainerID(name string) string {
	cid, err := exec.Command("docker", "inspect", "--format", "\"{{.Id}}\"", name).Output()
	if err != nil {
		return ""
	}

	return string(cid[1:len(cid)-2])
}

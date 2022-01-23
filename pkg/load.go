package pkg

import (
	"errors"
	"github.com/cilium/ebpf"
)

// Find pinned map associated to container and load
func LoadPinnedMap(loadedMap **ebpf.Map, name string, isIngress, isL3 bool) error {
        // Get container's full ID
        cgroupId := GetContainerID(name)
        if len(cgroupId) == 0 {
                return errors.New("Invalid container name or id!\n")
        }

	var path string
	pinPath := bpfPath + cgroupId
	if isL3 {
		if isIngress {
			path = pinPath + "/igs_map"
		}else{
			path = pinPath + "/egs_map"
		}
	}else{
		if isIngress {
			path = pinPath + "/igs_l4_map"
		}else{
			path = pinPath + "/egs_l4_map"
		}
	}

	// Load pinned map
	ret, err := ebpf.LoadPinnedMap(path, nil)
        if err != nil {
                return err
        }

	*loadedMap = ret
	return nil
}

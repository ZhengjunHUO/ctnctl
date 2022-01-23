/*
Copyright © 2022 ZhengjunHUO <firelouiszj@hotmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"fmt"
	"os"
	"net"

	"github.com/spf13/cobra"
	"github.com/ZhengjunHUO/ctnctl/pkg"
)

// blockCmd represents the block command
var blockCmd = &cobra.Command{
	Use:   "block [flags] <IP> <CONTAINER_NAME|CONTAINER_ID>",
	Short: "Add an ip to container's blacklist",
	Long: `Add an ip to container's blacklist`,
	Args: cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		// wait a -i or -e flag
		if isIngress == isEgress {
			fmt.Println("Need to specifiy ONE flag -i or -e!")
			os.Exit(1)
		}

		// accept at most one flag between -t and -u
		if isTCP && isUDP {
			fmt.Println("Can't have -t and -u in the same time!")
			os.Exit(1)
		}

		var ip string
		port := 0

		if isTCP {
			if tcpaddr, err := net.ResolveTCPAddr("tcp", args[0]); err != nil {
				fmt.Println("Not a valid tcp addr: ", err)
				os.Exit(1)
			}else{
				ip, port = tcpaddr.IP.String(), tcpaddr.Port
			}
		}else if isUDP{
			if udpaddr, err := net.ResolveUDPAddr("udp", args[0]); err != nil {
				fmt.Println("Not a valid udp addr: ", err)
				os.Exit(1)
			}else{
				ip, port = udpaddr.IP.String(), udpaddr.Port
			}
		}else{
			// check the input "ip" is valid
			if rslt := net.ParseIP(args[0]); rslt == nil {
				fmt.Println("Not a valid IP!")
				os.Exit(1)
			}
			ip = args[0]
		}

		//fmt.Printf("[DEBUG] IP: %s; Port: %v\n", ip, port)

		// Create and Pin / Load pinned bpf resources
		if err := pkg.CreateLinkIfNotExit(args[1]); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Add IP or IP:Port to firewall
		var err error
		if port != 0 {
			err = pkg.AddIPPort(ip, args[1], uint16(port), isIngress)
		}else{
			err = pkg.AddIP(ip, args[1], isIngress)
		}

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

var (
	isIngress bool
	isEgress bool
	isTCP bool
	isUDP bool
)

func init() {
	rootCmd.AddCommand(blockCmd)
	blockCmd.Flags().BoolVarP(&isIngress, "ingress", "i", false, "update the ingress table")
	blockCmd.Flags().BoolVarP(&isEgress, "egress", "e", false, "update the egress table")
	blockCmd.Flags().BoolVarP(&isTCP, "tcp", "t", false, "indicate a tcp rule")
	blockCmd.Flags().BoolVarP(&isUDP, "udp", "u", false, "indicate a udp rule")
}

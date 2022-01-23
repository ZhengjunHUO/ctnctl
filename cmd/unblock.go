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
	"os"
	"net"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/ZhengjunHUO/ctnctl/pkg"
)

// unblockCmd represents the unblock command
var unblockCmd = &cobra.Command{
	Use:   "unblock [flags] <IP> <CONTAINER_NAME|CONTAINER_ID>",
	Short: "Remove an ip from container's blacklist",
	Long: `Remove an ip from container's blacklist`,
	Args: cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		// wait a -i or -e flag
		if isIngressUnb == isEgressUnb {
			fmt.Println("Need to specifiy ONE flag -i or -e!")
			os.Exit(1)
		}

		// accept at most one flag between -t and -u
		if isTCPUnb && isUDPUnb {
			fmt.Println("Can't have -t and -u in the same time!")
			os.Exit(1)
		}

		var ip string
		port := 0

		if isTCPUnb {
			if tcpaddr, err := net.ResolveTCPAddr("tcp", args[0]); err != nil {
				fmt.Println("Not a valid tcp addr: ", err)
				os.Exit(1)
			}else{
				ip, port = tcpaddr.IP.String(), tcpaddr.Port
			}
		}else if isUDPUnb{
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
		// Add IP to firewall
		//var err error
		//if isIngressUnb {
		//	err = pkg.DelIP(args[0], args[1], true)
		//	pkg.DelIP(args[0], args[1], isIngressUnb)
		//}

		//if isEgressUnb {
		//	err = pkg.DelIP(args[0], args[1], false)
		//	pkg.DelIP(args[0], args[1], false)
		//}

		var err error
		if port != 0 {
			err = pkg.DelIPPort(ip, args[1], uint16(port), isIngressUnb)
		}else{
			err = pkg.DelIP(ip, args[1], isIngressUnb)
		}

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		/*
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		*/
	},
}

var (
	isIngressUnb bool
	isEgressUnb bool
	isTCPUnb bool
	isUDPUnb bool
)

func init() {
	rootCmd.AddCommand(unblockCmd)
	unblockCmd.Flags().BoolVarP(&isIngressUnb, "ingress", "i", false, "update the ingress table")
	unblockCmd.Flags().BoolVarP(&isEgressUnb, "egress", "e", false, "update the egress table")
	unblockCmd.Flags().BoolVarP(&isTCPUnb, "tcp", "t", false, "indicate a tcp rule")
	unblockCmd.Flags().BoolVarP(&isUDPUnb, "udp", "u", false, "indicate a udp rule")
}

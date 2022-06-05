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
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/ZhengjunHUO/ctnctl/internal/config"
	"github.com/ZhengjunHUO/ctnctl/pkg"
)

// loadfwCmd represents the loadfw command
var loadfwCmd = &cobra.Command{
	Use:   "loadfw --config <PATH_TO_CONFIG_FILE> [CONTAINER_NAME|CONTAINER_ID]",
	Short: "Load a list of firewall rules to to a container from a file",
	Long:	`Load a list of firewall rules to to a container from a file, if CONTAINER_NAME or 
		CONTAINER_ID is provided, the podName in the config file will be overrided`,
	//Args: cobra.MinimumNArgs(1),
	PreRun: config.ParseConfig,
	Run: func(cmd *cobra.Command, args []string) {
		fwconfig := config.DecodeConfig()

		podName := fwconfig.PodName
		if len(args) > 0 {
			podName = args[0]
		}

		// Create and Pin / Load pinned bpf resources
		if err := pkg.CreateLinkIfNotExit(podName); err != nil {
			os.Exit(1)
		}

		// Apply the parsed rules to container
		for _,v := range fwconfig.IngressRules.L3 {
			pkg.AddIP(string(v), podName, true)
		}

		for _,v := range fwconfig.IngressRules.L4 {
			pkg.AddIPPort(v.IP, podName, v.Port, true)
		}

		for _,v := range fwconfig.EgressRules.L3 {
			pkg.AddIP(string(v), podName, false)
		}

		for _,v := range fwconfig.EgressRules.L4 {
			pkg.AddIPPort(v.IP, podName, v.Port, false)
		}
	},
}

func init() {
	rootCmd.AddCommand(loadfwCmd)
	loadfwCmd.PersistentFlags().StringVar(&config.PathToConfigFile, "config", "", "path to config file")
        if err := loadfwCmd.MarkPersistentFlagRequired("config"); err != nil {
                log.Fatalln(err)
        }
}

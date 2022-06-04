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
	"github.com/spf13/cobra"
	"github.com/ZhengjunHUO/ctnctl/internal/config"
)

// loadfwCmd represents the loadfw command
var loadfwCmd = &cobra.Command{
	Use:   "loadfw --config <PATH_TO_CONFIG_FILE> <CONTAINER_NAME|CONTAINER_ID>",
	Short: "Load a list of firewall rules to to a container from a file",
	Long: `Load a list of firewall rules to to a container from a file`,
	Args: cobra.MinimumNArgs(1),
	PreRun: config.ParseConfig,
	Run: func(cmd *cobra.Command, args []string) {
		// TO IMPLEMENT
		// Apply the parsed rules to container
	},
}

func init() {
	rootCmd.AddCommand(loadfwCmd)
	loadfwCmd.PersistentFlags().StringVar(&config.PathToConfigFile, "config", "", "path to config file")
        if err := loadfwCmd.MarkPersistentFlagRequired("config"); err != nil {
                log.Fatalln(err)
        }
}

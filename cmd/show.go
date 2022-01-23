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
	"github.com/spf13/cobra"
	"github.com/ZhengjunHUO/ctnctl/pkg"
)

// showCmd represents the show command
var showCmd = &cobra.Command{
	Use:   "show <CONTAINER_NAME|CONTAINER_ID>",
	Short: "Show container's firewall rules",
	Long: `Show container's firewall rules`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pkg.PrintFirewall(args[0])
	},
}

func init() {
	rootCmd.AddCommand(showCmd)
}

package config

import (
	"os"
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var PathToConfigFile string

func ParseConfig(*cobra.Command, []string) {
	// Check if the file exist
	if _, err := os.Stat(PathToConfigFile); err != nil {
                log.Fatalln(err)
        }

	// Read content into viper
	viper.SetConfigFile(PathToConfigFile)
	log.Println("[DEBUG] Read: ", PathToConfigFile)
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalln(err)
	}

	log.Println("[DEBUG] TO IMPLEMENT")
	// TO IMPLEMENT
	// Use Viper to read config file
}

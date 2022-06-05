package config

import (
	"os"
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ZhengjunHUO/ctnctl/internal/models"
)

var PathToConfigFile string

// Locate the config file and read it into viper
func ParseConfig(*cobra.Command, []string) {
	// Check if the file exist
	if _, err := os.Stat(PathToConfigFile); err != nil {
                log.Fatalln(err)
        }

	// Read config's content into viper
	viper.SetConfigFile(PathToConfigFile)
	log.Println("[DEBUG] Read: ", PathToConfigFile)
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalln(err)
	}
}

// Deserialization content stored in viper to go struct
func DecodeConfig() models.FirewallConfig {
	var conf models.FirewallConfig
	if err := viper.Unmarshal(&conf); err != nil {
		log.Fatalln(err)
	}

	// TODO: add a validator to check the value read from config file
	return conf
}

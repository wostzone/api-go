// Package hubconfig with commandline configuration handling
package hubconfig

import (
	"flag"
	"os"
	"path"

	"github.com/sirupsen/logrus"
)

var flagsAreSet bool = false

// SetHubCommandlineArgs creates common hub commandline flag commands for parsing commandlines
//
// -c            /path/to/hub.yaml optional alt configuration, default is {home}/config/hub.yaml
// -home         /path/to/app/home    optional alternative application home folder/ Defa
// -certsFolder  /path/to/alt/certs   optional certificate folder, eg when using mqtt. Default is {home}/certs
// -configFolder /path/to/alt/config  optional alternative config, eg /etc/wost
// -address      localhost            optional message bus address
// -certPortMqtt 9883                 mqtt port for certificate authentication
// -unpwPortWS   9884                 websocket port for username/password authentication
// -logFile      /path/to/hub.log     optional logfile. Use to determine logs folder
// -logLevel warning                  for extra logging, default is hub loglevel
//
func SetHubCommandlineArgs(config *HubConfig) {
	// // workaround broken testing of go flags, as they define their own flags that cannot be re-initialized
	// // in test mode this function can be called multiple times. Since flags cannot be
	// // defined multiplte times, prevent redefining them just like testing.Init does.
	// if flagsAreSet {
	// 	return
	// }
	flagsAreSet = true
	// Flags -c and --home are handled separately in SetupConfig. It is added here to avoid flag parse error
	flag.String("c", "hub.yaml", "Set the hub configuration file ")
	flag.StringVar(&config.Home, "home", config.Home, "Application working `folder`")

	flag.StringVar(&config.CertsFolder, "certsFolder", config.CertsFolder, "Optional certificates directory for TLS")
	flag.StringVar(&config.ConfigFolder, "configFolder", config.ConfigFolder, "Plugin configuration `folder`")
	flag.StringVar(&config.MqttAddress, "mqttAddress", config.MqttAddress, "Message bus hostname or address")
	flag.IntVar(&config.MqttCertPort, "mqttCertPort", config.MqttCertPort, "MQTT TLS client port")
	flag.IntVar(&config.MqttUnpwPortWS, "mqttUnpwPortWS", config.MqttUnpwPortWS, "Websocket TLS client port")
	flag.StringVar(&config.LogFile, "logFile", config.LogFile, "Log to file")
	flag.StringVar(&config.PluginFolder, "pluginFolder", config.PluginFolder, "Alternate plugin `folder`. Empty to not load plugins.")
	flag.StringVar(&config.Loglevel, "logLevel", config.Loglevel, "Loglevel: {error|`warning`|info|debug}")
}

// LoadPluginConfig loads the hub and plugin configuration
//
// This uses the -home and -c commandline arguments commands without the
// flag package.
// Intended for plugins or Hub apps that have their own commandlines but
// still need to use the Hub's base configuration.
//
// The default hub config filename is 'hub.yaml' (const HubConfigName)
// The plugin configuration is the {pluginName}.yaml. If no pluginName is given it is ignored.
// The plugin logfile is stored in the hub logging folder using the pluginName.log filename
// This loads the hub commandline arguments with two special considerations:
//  - Commandline "-c"  specifies an alternative hub configuration file
//  - Commandline "--home" sets the home folder as the base of ./config, ./logs and ./bin directories
//       The homeFolder argument takes precedence
//
//  homeFolder overrides the default home folder
//     Leave empty to use parent of application binary. Intended for running tests.
//     The current working directory is changed to this folder
// pluginName is used as the ID in messaging and the plugin configuration filename
//     The plugin config file is optional. Sensible defaults will be used if not present.
// pluginConfig is the configuration to load. nil to only load the hub config.
// Returns the hub configuration and error code in case of error
func LoadPluginConfig(homeFolder string, pluginName string, pluginConfig interface{}) (*HubConfig, error) {
	hubConfig, err := LoadHubConfig(homeFolder)
	if err != nil {
		return hubConfig, err
	}

	// plugin config is optional
	if pluginName != "" && pluginConfig != nil {
		pluginConfigFile := path.Join(hubConfig.ConfigFolder, pluginName+".yaml")
		err := LoadConfig(pluginConfigFile, pluginConfig)
		if err != nil {
			logrus.Infof("Plugin configuration file %s not found. Ignored", pluginConfigFile)
		}
	}

	return hubConfig, nil
}

// LoadCommandlineConfig loads the hub and plugin configurations (See LoadPluginConfig)
// and applies commandline  parameters to allow modifying this configuration from the
// commandline.
// Returns the hub configuration and error code in case of error
func LoadCommandlineConfig(homeFolder string, pluginName string, pluginConfig interface{}) (*HubConfig, error) {
	hubConfig, err := LoadPluginConfig(homeFolder, pluginName, pluginConfig)
	if err != nil {
		return hubConfig, err
	}

	SetHubCommandlineArgs(hubConfig)

	// catch parsing errors, in case flag.ErrorHandling = flag.ContinueOnError
	err = flag.CommandLine.Parse(os.Args[1:])

	if err != nil {
		return hubConfig, err
	}

	// Second validation pass in case commandline argument messed up the config
	err = ValidateConfig(hubConfig)
	// if err != nil {
	// 	logrus.Errorf("Commandline configuration invalid: %s", err)
	// }

	// It is up to the app to change to the home directory.
	// os.Chdir(hubConfig.HomeFolder)

	// Last set the hub/plugin logging
	if pluginName != "" {
		logFolder := path.Dir(hubConfig.LogFile)
		logFileName := path.Join(logFolder, pluginName+".log")
		SetLogging(hubConfig.Loglevel, logFileName, hubConfig.TimeFormat)
	} else if hubConfig.LogFile != "" {
		SetLogging(hubConfig.Loglevel, hubConfig.LogFile, hubConfig.TimeFormat)
	}
	return hubConfig, err
}

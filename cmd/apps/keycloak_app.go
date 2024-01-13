// Copyright (c) arkade author(s) 2022. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

package apps

import (
	"fmt"

	"github.com/alexellis/arkade/pkg"
	"github.com/alexellis/arkade/pkg/apps"
	"github.com/alexellis/arkade/pkg/config"
	"github.com/alexellis/arkade/pkg/types"
	"github.com/sethvargo/go-password/password"

	"github.com/spf13/cobra"
)

func MakeInstallKeycloak() *cobra.Command {
	var keycloak = &cobra.Command{
		Use:          "keycloak",
		Short:        "Install keycloak ",
		Long:         `Install keycloak`,
		Example:      `  arkade install keycloak`,
		SilenceUsage: true,
	}

	keycloak.Flags().StringP("namespace", "n", "keycloak", "Namespace for the app")
	keycloak.Flags().StringP("user", "u", "bn_keycloak", "Username of admin user")
	keycloak.Flags().StringP("port", "P", "", "Database Port")
	keycloak.Flags().StringP("hostanme", "H", "", "Database hostname")
	keycloak.Flags().StringP("vendor", "v", "", "Database vendor")
	keycloak.Flags().StringP("database", "d", "bn_keycloak", "Database")
	keycloak.Flags().StringP("password", "p", "", "Overide the default random admin-password if this is set")
	keycloak.Flags().String("service-type", "ClusterIP", "Service Type for the main keycloak Service; ClusterIP, NodePort or LoadBalancer")
	keycloak.Flags().Bool("update-repo", true, "Update the helm repo")

	keycloak.Flags().StringArray("set", []string{}, "Use custom flags or override existing flags \n(example --set tls.enabled=false)")

	keycloak.RunE = func(command *cobra.Command, args []string) error {
		kubeConfigPath, _ := command.Flags().GetString("kubeconfig")
		if err := config.SetKubeconfig(kubeConfigPath); err != nil {
			return err
		}
		overrides := map[string]string{}
		namespace, err := command.Flags().GetString("namespace")
		if err != nil {
			return err
		}
		serviceType, err := command.Flags().GetString("service-type")
		if err != nil {
			return err
		}
		
		if serviceType != "ClusterIP" && serviceType != "NodePort" && serviceType != "LoadBalancer" {
			return fmt.Errorf("the service-type must be one of: ClusterIP, NodePort or LoadBalancer")
		}
		overrides["service.type"] = serviceType

		pass, _ := command.Flags().GetString("password")
		if len(pass) == 0 {
			var err error
			pass, err = password.Generate(25, 10, 0, false, true)
			if err != nil {
				return err
			}
		}
		overrides["database.password"] = pass

		adminUsername, err := command.Flags().GetString("user")
		if err != nil {
			return err
		}
		overrides["database.username"] = adminUsername

		database, err := command.Flags().GetString("database")
		if err != nil {
			return err
		}
		overrides["database.database"] = database

		databaseHostname, err := command.Flags().GetString("hostanme")
		if err != nil {
			return err
		}
		overrides["database.hostanme"] = databaseHostname

		databasePort, err := command.Flags().GetString("port")
		if err != nil {
			return err
		}
		overrides["database.port"] = databasePort

		databaseVendor, err := command.Flags().GetString("vendor")
		if err != nil {
			return err
		}
		overrides["database.vendor"] = databaseVendor

		updateRepo, _ := keycloak.Flags().GetBool("update-repo")


		customFlags, err := command.Flags().GetStringArray("set")
		if err != nil {
			return err
		}

		if err := config.MergeFlags(overrides, customFlags); err != nil {
			return err
		}

		keycloakOptions := types.DefaultInstallOptions().
			WithNamespace(namespace).
			WithHelmRepo("codecentric/keycloakx").
			WithHelmURL("https://codecentric.github.io/helm-charts/").
			WithHelmUpdateRepo(updateRepo).
			WithOverrides(overrides).
			WithKubeconfigPath(kubeConfigPath)

		_, err = apps.MakeInstallChart(keycloakOptions)

		if err != nil {
			return err
		}

		println(KeycloakInstallMsg)
		return nil
	}
	return keycloak
}

const KeycloakInfoMsg = `
# Open the UI:


`

const KeycloakInstallMsg = `=======================================================================
= keycloak has been installed                                        =
=======================================================================` +
	"\n\n" + KeycloakInfoMsg + "\n\n" + pkg.SupportMessageShort

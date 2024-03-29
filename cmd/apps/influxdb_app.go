// Copyright (c) arkade author(s) 2021. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

package apps

import (
	"strconv"

	"github.com/alexellis/arkade/pkg"
	"github.com/alexellis/arkade/pkg/apps"
	"github.com/alexellis/arkade/pkg/config"
	"github.com/alexellis/arkade/pkg/types"
	"github.com/spf13/cobra"
)

func MakeInstallinfluxdb() *cobra.Command {
	var influxdbApp = &cobra.Command{
		Use:          "influxdb",
		Short:        "Install influxdb",
		Long:         "Install Influxdb into your cluster",
		Example:      "arkade install influxdb --persistence",
		SilenceUsage: true,
	}

	influxdbApp.Flags().StringP("namespace", "n", "default", "The namespace to install chartmuseum (default: default")
	influxdbApp.Flags().Bool("update-repo", true, "Update the helm repo")
	influxdbApp.Flags().Bool("persistence", false, "Enable persistence for influxdb (default: false)")

	influxdbApp.RunE = func(command *cobra.Command, args []string) error {
		kubeConfigPath, _ := command.Flags().GetString("kubeconfig")
		namespace, _ := influxdbApp.Flags().GetString("namespace")
		updateRepo, _ := influxdbApp.Flags().GetBool("update-repo")
		persistence, _ := influxdbApp.Flags().GetBool("persistence")

		overrides := map[string]string{}
		overrides["persistence.enabled"] = strconv.FormatBool(persistence)

		customFlags, _ := command.Flags().GetStringArray("set")

		if err := config.MergeFlags(overrides, customFlags); err != nil {
			return err
		}

		influxdbOptions := types.DefaultInstallOptions().
			WithNamespace(namespace).
			WithHelmRepo("influxdata/influxdb").
			WithHelmURL("https://helm.influxdata.com/").
			WithHelmUpdateRepo(updateRepo).
			WithOverrides(overrides).
			WithKubeconfigPath(kubeConfigPath)

		_, err := apps.MakeInstallChart(influxdbOptions)
		if err != nil {
			return err
		}

		println(influxdbInstallMsg)
		return nil
	}

	return influxdbApp
}

const InfluxdbInfoMsg = `
# Get started with influxdb here:
https://github.com/influxdata/helm-charts/tree/master/charts/influxdb

InfluxDB can be accessed via port 8086 on the following DNS name from within your cluster:

  http://influxdb.default:8086

To port forward the API port to localhost:8086, run the following:

  kubectl port-forward -n default statefulset/influxdb 8086:8086

To view the logs for the InfluxDB pod, run the following:

  kubectl logs -f -n default statefulset/influxdb

`

const influxdbInstallMsg = `=======================================================================
= influxdb has been installed.                                   =
=======================================================================` +
	"\n\n" + InfluxdbInfoMsg + "\n\n" + pkg.SupportMessageShort

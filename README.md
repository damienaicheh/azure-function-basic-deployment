# Basic Azure Function deployment

> WARNING: This example use connection string, the best option is to use managed identities between Azure Function and the Storage Account using the Blob Storage Data Owner role.

Run the function locally:

```sh
func start
```

Build and package the project:

```sh
cd src/PingFunc/
```

```sh
dotnet build PingFunc.csproj --configuration Release --output ./output
```

Add a local.settings.json based on the template to be able to publish the Azure Function:
```sh
mv local.settings.json.tpl local.settings.json
```

Deploy the function to Azure Function:
```sh
az login --use-device-code
```

```sh
cd output
```

```sh
zip -r ./../output.zip .
```

```sh
az functionapp deployment source config-zip -g <resource_group> -n \
<app_name> --src <zip_file_path>
```

```sh
cd bicep
az deployment sub create --location francecentral --template-file main.bicep --parameters @bicep/parameters.json
```
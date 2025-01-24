targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Name which is used to generate a short unique hash for each resource')
param name string

@description('The environment deployed')
@allowed(['lab', 'dev', 'stg', 'prd'])
param environment string = 'dev'

@description('Name of the application')
param application string = 'hol'

@description('The location where the resources will be created.')
@allowed([
  'eastus'
  'eastus2'
  'francecentral'
  'swedencentral'
  'westus3'
])
param location string = 'francecentral'

@description('Optional. The tags to be assigned to the created resources.')
param tags object = {
  Deployment: 'bicep'
  Environment: environment
  Location: location
  Application: application
}

var resourceToken = toLower(uniqueString(subscription().id, name, environment, application))
var resourceSuffix = [
  toLower(environment)
  substring(toLower(location), 0, 2)
  substring(toLower(application), 0, 3)
  substring(resourceToken, 0, 8)
]
var resourceSuffixKebabcase = join(resourceSuffix, '-')
var resourceSuffixLowercase = join(resourceSuffix, '')

@description('The resource group.')
resource resourceGroup 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: 'rg-${resourceSuffixKebabcase}'
  location: location
  tags: tags
}

module func './modules/functions/host.bicep' = {
  name: 'func'
  scope: resourceGroup
  params: {
    planName: 'asp-${resourceSuffixKebabcase}'
    appName: 'func-${resourceSuffixKebabcase}'
    storageAccountName: 'st${resourceSuffixLowercase}'
    tags: tags
  }
}

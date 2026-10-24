// infra/azure/main.bicep
// Vorsyghta Azure Container Apps deployment with Nvidia LLM and Sentinel SIEM
param location string = resourceGroup().location
param prefix string = 'vorsyghta'
param postgresAdminPassword secureString
param nvidiaApiKey secureString
param vorsyghtaSecretKey secureString

var envName = '${prefix}env'
var apiName = '${prefix}api'
var webName = '${prefix}web'
var postgresName = '${prefix}pg'
var redisName = '${prefix}redis'
var lawName = '${prefix}law'

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: lawName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-03-01-preview' = {
  name: postgresName
  location: location
  sku: { name: 'Standard_B1ms', tier: 'Burstable' }
  properties: {
    version: '16'
    administratorLogin: 'vorsyghta'
    administratorLoginPassword: postgresAdminPassword
    storage: { storageSizeGB: 32 }
    network: { publicNetworkAccess: 'Enabled' }
  }
}

resource postgresDb 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2023-03-01-preview' = {
  parent: postgres
  name: 'vorsyghta'
}

resource redis 'Microsoft.Cache/Redis@2023-08-01' = {
  name: redisName
  location: location
  properties: {
    sku: { name: 'Basic', family: 'C', capacity: 0 }
    enableNonSslPort: false
  }
}

resource containerEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: envName
  location: location
  properties: {
    appLogsConfiguration: {
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

resource apiApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: apiName
  location: location
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8000
        transport: 'auto'
      }
      secrets: [
        { name: 'nvidiaApiKey', value: nvidiaApiKey }
        { name: 'vorsyghtaSecretKey', value: vorsyghtaSecretKey }
        { name: 'postgresPwd', value: postgresAdminPassword }
      ]
    }
    template: {
      containers: [
        {
          name: 'api'
          image: 'acrvorsyghta.azurecr.io/vorsyghta-api:local'
          env: [
            { name: 'DATABASE_URL', value: 'postgresql://vorsyghta:${secretref:postgresPwd}@${postgres.properties.fullyQualifiedDomainName}:5432/vorsyghta' }
            { name: 'REDIS_URL', value: 'redis://${redis.properties.hostName}:6380/0' }
            { name: 'VORSYGHTA_SECRET_KEY', secretRef: 'vorsyghtaSecretKey' }
            { name: 'DEFAULT_LLM_PROVIDER', value: 'nvidia' }
            { name: 'NVIDIA_API_KEY', secretRef: 'nvidiaApiKey' }
            { name: 'NVIDIA_BASE_URL', value: 'https://api.nvcf.nvidia.com/v1' }
            { name: 'ENVIRONMENT', value: 'production' }
            { name: 'LOG_LEVEL', value: 'INFO' }
            { name: 'SIEM_PLATFORM', value: 'sentinel' }
            { name: 'SIEM_URL', value: 'https://api.loganalytics.io/v1/workspaces/${logAnalytics.properties.customerId}' }
            { name: 'SIEM_INDEX', value: 'main' }
          ]
        }
      ]
      scale: { minReplicas: 1, maxReplicas: 3 }
    }
  }
}

resource webApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: webName
  location: location
  dependsOn: [
    apiApp
  ]
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 3000
        transport: 'auto'
      }
    }
    template: {
      containers: [
        {
          name: 'web'
          image: 'acrvorsyghta.azurecr.io/vorsyghta-web:local'
          env: [
            { name: 'VORSYGHTA_API_URL', value: 'https://${apiApp.properties.configuration.ingress.fqdn}' }
            { name: 'VORSYGHTA_ALLOW_INSECURE_INTERNAL_API', value: 'false' }
          ]
        }
      ]
      scale: { minReplicas: 1, maxReplicas: 2 }
    }
  }
}

output apiUrl string = 'https://${apiApp.properties.configuration.ingress.fqdn}'
output webUrl string = 'https://${webApp.properties.configuration.ingress.fqdn}'
output logAnalyticsWorkspaceId string = logAnalytics.properties.customerId

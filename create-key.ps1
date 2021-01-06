# Variables

$apikey = '...'
$kms = 'nnnnnnnn-nnnn-nnnn-nnnn-nnnnnnnnnnnn'
$crk = 'nnnnnnnn-nnnn-nnnn-nnnn-nnnnnnnnnnnn'

# URIs and script level settings

$tokenURI = 'https://private.iam.cloud.ibm.com/identity/token'
$kmsURIbase = 'https://private.us-south.kms.cloud.ibm.com/api/v2/keys/'
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Check parameters

if($args.count -ne 1) {
  Write-Output "`nUsage:`n  ./create-key.ps1 key-moniker`n"
  exit
}

# Let's not create two keys with the same moniker

$moniker = $args[0]
Get-VBREncryptionKey | ForEach-Object {
  if($_.Description.StartsWith($moniker + " | ")) {
    $key = $_
    return
  }
}

if($key) {
  Write-Output "You already have a key with that moniker`n"
  exit
}

# Exchange IBM Cloud API key for token

$headers = @{Accept='application/json'}
$body = @{grant_type='urn:ibm:params:oauth:grant-type:apikey'; apikey=$apikey}
$tokenResponse = Invoke-RestMethod -Uri $tokenURI -Method POST -Body $body -Headers $headers

# Perform wrap operation with empty payload to generate an AES 256 key that will be used as password

$headers = @{Accept='application/json'; 'content-type'='application/vnd.ibm.kms.key_action_wrap+json'; 'bluemix-instance'=$kms; Authorization=("Bearer " + $tokenResponse.access_token); 'correlation-id'=[guid]::NewGuid()}
$body = @{}
$wrapResponse = Invoke-RestMethod -Uri ($kmsURIbase + $crk + "/actions/wrap") -Method POST -Body (ConvertTo-Json $body) -Headers $headers
$plaintext = ConvertTo-SecureString $wrapResponse.plaintext -AsPlainText -Force
$wdek = $wrapResponse.ciphertext
Remove-Variable wrapResponse

# Store this key as a new Veeam encryption key. Retain it in base64 format for simplicity.

Add-VBREncryptionKey -Password $plaintext -Description ($moniker + " | " + $wdek)

Write-Output ("Created new key " + $moniker)


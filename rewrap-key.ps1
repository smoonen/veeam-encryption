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
  Write-Output "`nUsage:`n  ./rewrap-key.ps1 key-moniker`n"
  exit
}

# Identify which key is to be rewrapped

$moniker = $args[0]
Get-VBREncryptionKey | ForEach-Object {
  if($_.Description.StartsWith($moniker + " | ")) {
    $key = $_
    return
  }
}

if(!$key) {
  Write-Output "No key found with that moniker`n"
  exit
}

# Extract its wrapped form
$wdek = $key.Description.Substring($moniker.length + 3)

# Exchange IBM Cloud API key for token

$headers = @{Accept='application/json'}
$body = @{grant_type='urn:ibm:params:oauth:grant-type:apikey'; apikey=$apikey}
$tokenResponse = Invoke-RestMethod -Uri $tokenURI -Method POST -Body $body -Headers $headers

# Perform rewrap operation to rewrap our key
# If this operation fails, it is possible your root key has been revoked and you should destroy the Veeam key

$headers = @{Accept='application/json'; 'content-type'='application/vnd.ibm.kms.key_action_rewrap+json'; 'bluemix-instance'=$kms; Authorization=("Bearer " + $tokenResponse.access_token); 'correlation-id'=[guid]::NewGuid()}
$body = @{ciphertext=$wdek}
$rewrapResponse = Invoke-RestMethod -Uri ($kmsURIbase + $crk + "/actions/rewrap") -Method POST -Body (ConvertTo-Json $body) -Headers $headers
$newWdek = $rewrapResponse.ciphertext
Remove-Variable rewrapResponse

# Update the existing description of the Veeam encryption key to reflect the updated wrapped version

Set-VBREncryptionKey -EncryptionKey $key.Description -Description ($moniker + " | " + $newWdek)

Write-Output ("Rewrapped key " + $moniker)


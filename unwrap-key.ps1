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
  Write-Output "`nUsage:`n  ./unwrap-key.ps1 wrapped-key-material`n"
  exit
}

# Exchange IBM Cloud API key for token

$headers = @{Accept='application/json'}
$body = @{grant_type='urn:ibm:params:oauth:grant-type:apikey'; apikey=$apikey}
$tokenResponse = Invoke-RestMethod -Uri $tokenURI -Method POST -Body $body -Headers $headers

# Perform unwrap operation

$headers = @{Accept='application/json'; 'content-type'='application/vnd.ibm.kms.key_action_unwrap+json'; 'bluemix-instance'=$kms; Authorization=("Bearer " + $tokenResponse.access_token); 'correlation-id'=[guid]::NewGuid()}
$body = @{ciphertext=$args[0]}
$unwrapResponse = Invoke-RestMethod -Uri ($kmsURIbase + $crk + "/actions/unwrap") -Method POST -Body (ConvertTo-Json $body) -Headers $headers

Write-Output ("Plaintext key: " + $unwrapResponse.plaintext)


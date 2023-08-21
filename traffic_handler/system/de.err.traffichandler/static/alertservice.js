function generateNewAccessKey() {
    fetch('/rest/v1/alertservice/generate_key', {
        method: 'POST'
    })
    .then(response => {
        if (response.ok) {
            // Reload the page after successful key generation
            location.reload();
        } else {
            // Handle error response if needed
            console.error('Error generating new Access Key.');
        }
    })
    .catch(error => {
        console.error('Error sending the request:', error);
    });
}
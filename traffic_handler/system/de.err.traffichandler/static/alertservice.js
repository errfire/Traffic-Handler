function generateNewAccessKey() {
    fetch('/rest/v1/alertservice/generate_key', {
        method: 'POST'
    })
    .then(response => {
        if (response.ok) {
            location.reload();
        } else {

            console.error('Error generating new Access Key.');
        }
    })
    .catch(error => {
        console.error('Error sending the request:', error);
    });
}
// Funktion zum Abrufen der Daten vom Backend
        function fetchData() {
            axios.post('/get_data', {
                // Hier können weitere Parameter für den Request übergeben werden
            })
            .then(function (response) {
                // Hier werden die empfangenen Daten in der Webseite angezeigt
                document.getElementById('weatherInfo').textContent = JSON.stringify(response.data.weather);
                document.getElementById('mapImage').src = response.data.map.image_url;
                document.getElementById('routeInfo').textContent = JSON.stringify(response.data.route);
            })
            .catch(function (error) {
                console.log(error);
            });
        }

        // Daten beim Laden der Seite abrufen
        fetchData();
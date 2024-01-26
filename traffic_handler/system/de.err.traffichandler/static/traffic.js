function getLocation() {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(showPosition);
    } else {
        alert("Geolocation wird von diesem Browser nicht unterstützt.");
    }
}

function showPosition(position) {
    var latitude = position.coords.latitude;
    var longitude = position.coords.longitude;

    var map = L.map('map').setView([latitude, longitude], 13);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 18,
        attribution: '&copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a> contributors'
    }).addTo(map);

    L.marker([latitude, longitude]).addTo(map)
        .bindPopup('Ihr aktueller Standort')
        .openPopup();

    axios.get('/rest/v1/get_constructions')
        .then(function (response) {
            var constructions = response.data;

            constructions.forEach(function (construction) {
                var constructionType = construction.type;
                var latitude = parseFloat(construction.latitude);
                var longitude = parseFloat(construction.longitude);

                var customIcon;

                if (constructionType === 'Baustelle') {
                    customIcon = L.icon({
                        iconUrl: 'static/baustelle.jpg',
                        iconSize: [32, 32],
                        iconAnchor: [16, 32],
                        popupAnchor: [0, -32]
                    });
                } else if (constructionType === 'Gefahrenstelle') {
                    customIcon = L.icon({
                        iconUrl: 'static/warning.png',
                        iconSize: [32, 32],
                        iconAnchor: [16, 32],
                        popupAnchor: [0, -32]
                    });
                } else if (constructionType === 'Einbahnstrasse') {
                    customIcon = L.icon({
                        iconUrl: 'static/einbahnstrasse.jpg',
                        iconSize: [60, 32],
                        iconAnchor: [16, 32],
                        popupAnchor: [0, -32]
                    });
                } else if (constructionType === 'Durchfahrtsverbot') {
                    customIcon = L.icon({
                        iconUrl: 'static/durchfahrtsverbot.jpg',
                        iconSize: [32, 32],
                        iconAnchor: [16, 32],
                        popupAnchor: [0, -32]
                    });

                }
                L.marker([latitude, longitude], { icon: customIcon }).addTo(map)
                    .bindPopup('Titel: ' + construction.title + '<br>Adresse: ' + construction.strasse +", "+ construction.plz +" "+construction.ort + '<br>Type: ' + construction.type)
                    .openPopup();
            });
        })
        .catch(function (error) {
            console.error('Fehler beim Abrufen der Verkehrslage aus der Datenbank: ', error);
        });
}


function loadRoute() {

    fetch('/rest/v1/route/alert')
        .then(response => response.json())
        .then(data => {
            if (data.latitude && data.longitude) {

                var routePoints = [
                    [latitude, longitude],
                    [data.latitude, data.longitude]
                ];

                if (!map.hasLayer(route)) {
                    var route = L.polyline(routePoints, { color: 'blue' }).addTo(map);
                } else {
                    route.setLatLngs(routePoints);
                }
            }
        })
        .catch(error => {
            console.error('Fehler beim Laden der Koordinaten: ', error);
        });
}


loadRoute();
    setInterval(loadRoute, 30000);




getLocation();
var map;
var customIcon = L.icon({
    iconUrl: 'static/baustelle.jpg',
});

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

    map = L.map('map').setView([latitude, longitude], 13);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 18,
        attribution: '&copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a> - ERR-FIRE Traffic Handler'
    }).addTo(map);

    L.marker([latitude, longitude]).addTo(map)
        .bindPopup('Ihr aktueller Standort')
        .openPopup();
    setTimeout(function() {
        navigator.geolocation.getCurrentPosition(showPosition);
    }, 5000);
    getLocation();

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
                    .bindPopup('Titel: ' + construction.title + '<br>Adresse: ' + construction.strasse + ", " + construction.plz + " " + construction.ort + '<br>Type: ' + construction.type)
                    .openPopup();
            });
        })
        .catch(function (error) {
            console.error('Fehler beim Abrufen der Verkehrslage aus der Datenbank: ', error);
        });


}
function loadDrawings() {
    axios.get('/rest/v1/get_drawings')
        .then(function (response) {
            var drawings = response.data;

            drawings.forEach(function (drawing) {
                var geometryString = drawing.geometry;
                var geometry = JSON.parse(geometryString);

                if (geometry.type === 'Point') {
                    var coordinates = geometry.coordinates;
                    addMarkerToMap(coordinates);
                    console.log('Point');
                } else if (geometry.type === 'LineString') {
                    var coordinates = geometry.coordinates;
                    addLineToMap(coordinates);
                    console.log('LineString');
                    console.log(drawing)
                }
            });
        })
        .catch(function (error) {
            console.error('Fehler beim Laden der Zeichnungen: ', error);
        });
}

function addMarkerToMap(coordinates) {
    L.marker(coordinates, { icon: customIcon }).addTo(map);
}

function addLineToMap(coordinates) {
    var latlngs = coordinates.map(coord => [coord[1], coord[0]]);
    var polyline = L.polyline(latlngs, {color: 'red', weight: 5}).addTo(map);
}

getLocation();
loadDrawings();

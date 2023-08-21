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

    // Individuelles Warzeichen (Icon) erstellen
    var customIcon = L.icon({
        iconUrl: 'static/warning.png', // Pfad zur individuellen Icon-Datei (PNG- oder SVG-Datei) im Verzeichnis "images"
        iconSize: [32, 32], // Größe des Icons [Breite, Höhe]
        iconAnchor: [16, 32], // Position des Ankertpunkts im Verhältnis zur Icon-Größe [x, y]
        popupAnchor: [0, -32] // Position des Popups relativ zum Ankertpunkt [x, y]
    });

    // Marker mit dem individuellen Warzeichen für den aktuellen Standort hinzufügen
    L.marker([latitude, longitude]).addTo(map)
        .bindPopup('Aktueller Standort')
        .openPopup();
      axios.get('/get_constructions')  // Hier kannst du eine Route auf deinem Server erstellen, die alle Baustellen aus der Datenbank abruft
        .then(function (response) {
            var constructions = response.data;
            console.log(constructions)

            constructions.forEach(function (construction) {
                var latitude = parseFloat(construction.latitude);
                var longitude = parseFloat(construction.longitude);

                // Neuen Marker hinzufügen
                L.marker([latitude, longitude], { icon: customIcon }).addTo(map)
                    .bindPopup('Titel: ' + construction.title + '<br>Adresse: ' + construction.address)
                    .openPopup();
            });
        })
        .catch(function (error) {
            console.error('Fehler beim Abrufen der Baustellen aus der Datenbank: ', error);
        });


}
// Funktion zum Laden der Route basierend auf Koordinaten von /rest/v1/route/alert
function loadRoute() {
    // AJAX-Anfrage an den Server, um Koordinaten zu erhalten
    fetch('/rest/v1/route/alert')
        .then(response => response.json())
        .then(data => {
            if (data.latitude && data.longitude) {
                // Route laden und anzeigen, wenn Koordinaten vorhanden sind
                var routePoints = [
                    [latitude, longitude], // Startpunkt (aktueller Standort)
                    [data.latitude, data.longitude] // Zielpunkt (aus den erhaltenen Koordinaten)
                ];

                // Route hinzufügen oder aktualisieren
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

// Route initial laden und alle 5 Sekunden aktualisieren
loadRoute();
    setInterval(loadRoute, 5000);



// getLocation-Funktion aufrufen, um die Karte zu initiieren
getLocation();
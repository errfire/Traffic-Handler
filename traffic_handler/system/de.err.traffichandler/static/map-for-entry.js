var map;
var polyline = null;

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
        attribution: '&copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a> contributors'
    }).addTo(map);

    L.marker([latitude, longitude]).addTo(map)
        .bindPopup('Ihr aktueller Standort')
        .openPopup()

    var drawnItems = new L.FeatureGroup().addTo(map);
    var drawControl = new L.Control.Draw({
        draw: {
            polygon: false,
            circle: false,
            marker: false,
        },
        edit: {
            featureGroup: drawnItems
        }
    });

    map.addControl(drawControl);

    map.on(L.Draw.Event.CREATED, function (event) {
        var layer = event.layer;
        drawnItems.addLayer(layer);

        var geometry = layer.toGeoJSON().geometry;

        saveDrawingToDatabase(geometry);
    });

}
function saveDrawingToDatabase(geometry) {
    var drawingData = {
        geometry: JSON.stringify(geometry)
    };

    axios.post('/rest/v1/save_drawing', drawingData)
        .then(function (response) {
            console.log('Zeichnung erfolgreich in der Datenbank gespeichert:', response.data);
        })
        .catch(function (error) {
            console.error('Fehler beim Speichern der Zeichnung:', error);
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

function addDrawingToMap(drawing) {
    var geometryString = drawing.geometry;
    var geometry = JSON.parse(geometryString);

    if (geometry.type === 'Point') {
        var coordinates = geometry.coordinates;
        addMarkerToMap(coordinates);
        console.log('Point');
    } else if (geometry.type === 'LineString') {
        var coordinates = geometry.coordinates;
        var polyline = addLineToMap(coordinates);
        console.log('LineString');
        console.log(drawing);

        polyline.on('click', function () {
            deleteDrawing(drawing.id);
            map.removeLayer(polyline);
        });
    }
}


function addLineToMap(coordinates) {
    var latlngs = coordinates.map(coord => [coord[1], coord[0]]);
    var polyline = L.polyline(latlngs, {color: 'red', weight: 5}).addTo(map);
    return polyline;
}

function deleteDrawing(drawingId) {
    axios.delete('/rest/v1/delete_drawing/' + drawingId)
        .then(function (response) {
            console.log('Zeichnung erfolgreich gelöscht:', response.data);
            removeDrawingFromMap(drawingId);
        })
        .catch(function (error) {
            console.error('Fehler beim Löschen der Zeichnung:', error);
        });
}

function removeDrawingFromMap(drawingId) {
    map.eachLayer(function (layer) {
        if (layer instanceof L.Polyline && layer.drawingId === drawingId) {
            map.removeLayer(layer);
        }
    });
}

function addMarkerToMap(coordinates) {
    L.marker(coordinates, { icon: customIcon }).addTo(map);
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
                    var route = L.polyline(routePoints, { color: 'red' }).addTo(map);
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
loadDrawings();

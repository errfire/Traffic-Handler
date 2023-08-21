// alert.js

// Diese Funktion überprüft den Serverstatus und zeigt entsprechende Meldungen an.
function checkServerStatus() {
  // Hier setzen Sie den Server-Endpunkt für den Statusabfrage-Aufruf
  const serverStatusEndpoint = "/api/server/status";

  // Axios wird verwendet, um eine GET-Anfrage an den Server zu senden
  axios
    .get(serverStatusEndpoint)
    .then((response) => {
      const status = response.data.status;
      if (status === "false") {
        // Wenn der Serverstatus "False" ist, zeigen Sie die entsprechende Meldung an
        displayErrorMessage("Kein Alarmserver aktiviert - Lokaler Demomodus ausgewählt");
      } else if (response.status === 401) {
        // Wenn eine 401-Antwort vom Server erhalten wurde, zeigen Sie die Fehlermeldung an
        displayErrorMessage("Fehler - Zugriff ungültig");
      } else {
        // Hier können Sie weitere Meldungen basierend auf der Serverantwort anzeigen oder andere Aktionen durchführen
        // Zum Beispiel: displaySuccessMessage("Erfolgreich verbunden!");
      }
    })
    .catch((error) => {
      console.error("Fehler beim Abrufen des Serverstatus:", error);
      // Hier können Sie eine Fehlermeldung anzeigen, wenn die Anfrage fehlschlägt
    });
}

// Diese Funktion zeigt eine Fehlermeldung auf der Webseite an
function displayErrorMessage(message) {
  const errorDiv = document.createElement("div");
  errorDiv.classList.add("alert", "alert-danger");
  errorDiv.setAttribute("role", "alert");
  errorDiv.textContent = message;

  const container = document.querySelector(".container");
  container.prepend(errorDiv);
}

// Diese Funktion zeigt eine Erfolgsmeldung auf der Webseite an
function displaySuccessMessage(message) {
  const successDiv = document.createElement("div");
  successDiv.classList.add("alert", "alert-success");
  successDiv.setAttribute("role", "alert");
  successDiv.textContent = message;

  const container = document.querySelector(".container");
  container.prepend(successDiv);
}

// Diese Funktion wird aufgerufen, wenn die Webseite geladen wird, um den Serverstatus zu überprüfen
function initialize() {
  checkServerStatus();
}

// Rufen Sie die Initialisierungsfunktion auf, wenn die Webseite geladen wird
window.onload = initialize;

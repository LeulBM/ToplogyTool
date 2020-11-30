import db
from flask import Flask, render_template, make_response, redirect, url_for, request

app = Flask(__name__)
session = db.createDBSession()

@app.route('/')
def home():
    alerts = db.queryAlerts(session)
    map_entires = db.queryMapEntries(session)
    devices = db.queryDevices(session)
    node_entries = []
    for device in devices:
        node_entries.append({"name":device.source_id,"group":1})
    
    links_entries = []
    for entry in map_entires:
        links_entries.append({"source":entry.source_device_id-1,"target":entry.destination_device_id-1})
    entires = {"nodes":node_entries,"links":links_entries}
    return render_template('index.html', alerts = alerts, entires=entires, devices=devices)
    

@app.route('/clear_alerts',methods = ['POST'])
def clear_alerts():
    alert_id = request.form['alert_id']
    alert = db.queryAlert(session,alert_id)
    db.readAlert(session,alert)
    return redirect(url_for('home'))

@app.route('/<page_name>')
def other_page(page_name):
    response = make_response('The page named %s does not exist.' \
                             % page_name, 404)
    return response

if __name__ == '__main__':
    app.run(debug=True)
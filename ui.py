import db
from flask import Flask, render_template, make_response, redirect, url_for, request

app = Flask(__name__)
#session = db.createDBSession()
AUTO_REFRESH=False

@app.route('/')
def home():
    session = db.createDBSession()

    alerts = db.queryAlerts(session)
    map_entires = db.queryMapEntries(session)
    devices = db.queryDevices(session)
    session.close()
    
    node_entries = []
    legend_entries = []
    for device in devices:
        node_entries.append({"id":device.device_id,"name":device.source_id,"group":device.pan_id})
        if device.pan_id not in legend_entries:
            legend_entries.append(device.pan_id)
    links_entries = []
    for entry in map_entires:
        links_entries.append({"source":entry.source_device_id,"target":entry.destination_device_id})
    entires = {"nodes":node_entries,"links":links_entries,"legend":legend_entries}
    return render_template('index.html', alerts = alerts, entires=entires, devices=devices,auto_refresh_bool=AUTO_REFRESH)
    

@app.route('/clear_alerts',methods = ['POST'])
def clear_alerts():

    session = db.createDBSession()

    alert_id = request.form['alert_id']
    alert = db.queryAlert(session,alert_id)
    db.readAlert(session,alert)

    session.close()
    return redirect(url_for('home'))

@app.route('/auto_refresh')
def auto_refresh():
    global AUTO_REFRESH
    if AUTO_REFRESH:
        AUTO_REFRESH=False
    else:
        AUTO_REFRESH=True
    return redirect(url_for('home'))

@app.route('/<page_name>')
def other_page(page_name):
    response = make_response('The page named %s does not exist.' \
                             % page_name, 404)
    return response

if __name__ == '__main__':
    app.run(debug=True)

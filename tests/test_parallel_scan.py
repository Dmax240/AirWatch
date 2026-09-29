"""Check that a running recovery does not lock out a second network scan."""
import os
from pathlib import Path
import tempfile

with tempfile.TemporaryDirectory(prefix='airwatch-parallel-') as folder:
    os.environ['AIRWATCH_PREFERENCES_FILE']=str(Path(folder)/'preferences.json')
    import airwatch
    from airwatch import AirWatch

    app=AirWatch()
    recovery=app.recovery_panel
    recovery.job_running=True
    recovery.ready_hash='old-network.hc22000'
    recovery.ready_target_bssid='001122334455'
    recovery.active_target={'bssid':'00:11:22:33:44:55','essid':'Original network'}
    recovery.target_var.set('Selected: Original network')
    app.selected_target={'bssid':'00:11:22:33:44:55','essid':'Original network',
                         'channel':'1','security':'WPA2 PSK','signal':'-40'}
    app.navigate('Networks')
    app.update()
    app.guided.refresh()
    assert str(app.guided.primary.cget('state'))=='normal'
    assert str(app.guided.scan_start.cget('state'))=='normal'
    assert app.guided.action_var.get()=='⌕ Find networks',repr(app.guided.action_var.get())
    assert app.start_btn.instate(['!disabled'])

    calls=[]
    app.guided.prepare_adapter=lambda:True
    app.start_capture=lambda focused=False:calls.append(focused)
    app.guided.primary.invoke()
    assert calls==[False] and recovery.job_running

    # Exercise the actual capture entry point without touching a radio.
    original_wait=app._wait_task
    original_poll=app._poll
    original_tool=airwatch.Airodump
    class FakeCapture:
        pass
    app.start_capture=AirWatch.start_capture.__get__(app)
    app._wait_task=lambda _work:FakeCapture()
    app._poll=lambda:None
    airwatch.Airodump='/bin/true'
    app.interfaces[app.interface.get()]['mode']='monitor'
    app.outdir.set(folder)
    app.start_capture()
    assert isinstance(app.proc,FakeCapture) and recovery.job_running
    app.proc=None
    app.capture_focused=False
    app._wait_task=original_wait
    app._poll=original_poll
    airwatch.Airodump=original_tool
    app.start_capture=lambda focused=False:calls.append(focused)

    new={'bssid':'66:77:88:99:aa:bb','essid':'Second network',
         'channel':'6','security':'WPA2 PSK','signal':'-50'}
    app.table.insert('','end',iid=new['bssid'],values=tuple(new[key] for key in
                     ('bssid','channel','security','signal','essid')))
    app.table.selection_set(new['bssid'])
    app.select_target()
    assert app.selected_target['bssid']==new['bssid']
    assert recovery.ready_hash=='old-network.hc22000'
    assert recovery.target_var.get()=='Selected: Original network'

    app.navigate('Capture')
    app.guided.act()
    assert calls==[False,True] and not recovery.pause_requested
    app.navigate('Recovery')
    app.guided.refresh()
    assert app.guided.context_var.get()=='Original network'

    cap=Path(folder)/'new-01.cap'
    cap.write_bytes(b'pcap sample')
    recovery.defer_capture(str(Path(folder)/'new'),new)
    assert recovery.pending_capture and recovery.capture_path.get()==''
    app.guided.refresh()
    assert app.guided.new_capture_btn.instate(['disabled'])
    recovery.job_running=False
    app.guided.refresh()
    assert app.guided.new_capture_btn.instate(['!disabled'])
    analyzed=[]
    recovery.analyze=lambda:analyzed.append(recovery.capture_path.get())
    app.guided.new_capture_btn.invoke()
    assert analyzed==[str(cap)] and recovery.ready_hash is None
    app.close()

print('Parallel scan navigation and deferred capture passed.')

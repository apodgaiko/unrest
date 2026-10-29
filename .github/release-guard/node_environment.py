"""Construct role data after its parent, project, node and attempt are bound."""


def environment(ambient,home,project,node,role,attempt):
    result={key:ambient[key] for key in ('HOME','LANG','LC_ALL','NO_PROXY','PATH','SSL_CERT_DIR',
        'SSL_CERT_FILE','TEMP','TMP','TMPDIR') if key in ambient}
    result.update(UNREST_CAPABILITY_PROFILE='safe',UNREST_CAPABILITY_POLICY_VERSION='1',
        UNREST_HOME=str(home),UNREST_PROJECT_ID=project,UNREST_MISSION_ID='mission-001')
    runtime=home/'projects'/project/'.unrest-runtime/missions/mission-001'
    if role=='terminal_reviewer':
        result['UNREST_TERMINAL_REVIEW_PATH']=str(runtime/'terminal-reviews'/(attempt+'.json'))
    else:
        result.update(UNREST_NODE_ID=node,UNREST_NODE_TYPE=role,
            UNREST_HANDOFF_PATH=str(runtime/'attempts'/(attempt+'__'+node+'.json')))
    return result

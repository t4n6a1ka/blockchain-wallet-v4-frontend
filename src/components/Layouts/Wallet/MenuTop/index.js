import React from 'react'
import {connect} from 'react-redux'
import { bindActionCreators } from 'redux'

import { actions } from 'data'
import MenuTop from './template.js'

class MenuTopContainer extends React.Component {
  constructor (props) {
    super(props)
    this.openSendBitcoin = this.openSendBitcoin.bind(this)
    this.openRequestBitcoin = this.openRequestBitcoin.bind(this)
  }

  openSendBitcoin () {
    this.props.actions.toggleModal({ modalType: 'sendBitcoin' })
  }

  openRequestBitcoin () {
    this.props.actions.toggleModal({ modalType: 'requestBitcoin' })
  }

  render () {
    return <MenuTop openSendBitcoin={this.openSendBitcoin} openRequestBitcoin={this.openRequestBitcoin} />
  }
}

const mapDispatchToProps = (dispatch) => ({
  actions: bindActionCreators(actions.modals, dispatch)
})

export default connect(undefined, mapDispatchToProps)(MenuTopContainer)

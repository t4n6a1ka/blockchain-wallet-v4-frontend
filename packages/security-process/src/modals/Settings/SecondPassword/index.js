import React from 'react'
import { connect } from 'react-redux'
import { bindActionCreators, compose } from 'redux'
import { actions } from 'data'
import modalEnhancer from 'providers/ModalEnhancer'
import SecurityModuleContext from 'providers/SecurityModule'
import SecondPassword from './template.js'
import * as C from 'services/AlertService'

class SecondPasswordContainer extends React.PureComponent {
  constructor (props) {
    super(props)
    this.state = { secondPassword: '' }
    this.handleClick = this.handleClick.bind(this)
    this.handleChange = this.handleChange.bind(this)
  }

  handleClick () {
    if (this.context.verifySecondPassword(this.state.secondPassword)) {
      this.props.walletActions.submitSecondPassword(this.state.secondPassword)
      this.props.modalActions.closeModal()
    } else {
      this.props.alertActions.displayError(C.SECOND_PASSWORD_INVALID_ERROR)
      this.setState({ secondPassword: '' })
    }
  }

  handleChange (event) {
    this.setState({ secondPassword: event.target.value })
  }

  render () {
    return (
      <SecondPassword
        {...this.props}
        handleClick={this.handleClick}
        handleChange={this.handleChange}
        value={this.state.secondPassword}
      />
    )
  }
}

SecondPasswordContainer.contextType = SecurityModuleContext

const mapDispatchToProps = dispatch => ({
  alertActions: bindActionCreators(actions.alerts, dispatch),
  modalActions: bindActionCreators(actions.modals, dispatch),
  walletActions: bindActionCreators(actions.wallet, dispatch)
})

const enhance = compose(
  modalEnhancer('SecondPassword'),
  connect(
    null,
    mapDispatchToProps
  )
)

export default enhance(SecondPasswordContainer)

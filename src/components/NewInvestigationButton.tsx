import {useNavigate} from 'react-router-dom'
import {Icon} from './Icons'

export default function NewInvestigationButton(){
  const navigate=useNavigate()
  return <button className="new-investigation" type="button" onClick={()=>navigate('/investigations/new')} aria-label="Start a new investigation"><Icon name="plus" width={16} height={16}/>New investigation</button>
}

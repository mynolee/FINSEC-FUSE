package com.finsec.fuse.payment;

import static com.finsec.fuse.payment.PaymentValues.*;
import com.finsec.fuse.persistence.Db;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Caller holds execution_gate and the workflow row; releases never refund consumed stage costs. */
@Service
public class PaymentRiskService {
    private final Db db;
    public PaymentRiskService(Db db) {this.db=db;}
    @Transactional(propagation=Propagation.MANDATORY)
    public int releaseLocked(UUID workflowId,Instant now) {
        if(db.one("select id from mock_payment where workflow_id=?",workflowId).isPresent()) return 0;
        int total=0;
        for(var reservation:db.query("select * from payment_reservation where workflow_id=? and status='RESERVED' for update",workflowId)) {
            int points=integer(reservation,"points");
            db.update("update payment_reservation set status='RELEASED',completed_at=? where id=?",Timestamp.from(now),uuid(reservation,"id"));
            db.update("insert into risk_ledger(id,workflow_id,generation,stage,event_type,points,action_id,run_id,reservation_id,created_at) values(?,?,?,'PAYMENT','RELEASE',?,?,?,?,?)",
                UUID.randomUUID(),workflowId,integer(reservation,"generation"),points,uuid(reservation,"execution_action_id"),uuid(reservation,"run_id"),uuid(reservation,"id"),Timestamp.from(now));
            total+=points;
        }
        if(total>0) {
            db.update("update workflow set reserved_risk=reserved_risk-?,updated_at=? where id=?",total,Timestamp.from(now),workflowId);
            db.update("update workflow_stage set reserved_points=reserved_points-? where workflow_id=? and stage='PAYMENT'",total,workflowId);
        }
        return total;
    }
}

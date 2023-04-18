use crate::{DnsError, DnsMessageHeader, DnsQuestion, DnsRecord, DnsResponseCode};
use fixed_buffer::FixedBuf;
use std::convert::TryFrom;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DnsMessage {
    pub header: DnsMessageHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub name_servers: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}
impl DnsMessage {
    /// # Errors
    /// Returns an error when there are more than 65,536 questions.
    pub fn question_count(&self) -> Result<u16, DnsError> {
        u16::try_from(self.questions.len()).map_err(|_| DnsError::TooManyQuestions)
    }

    /// # Errors
    /// Returns an error when `buf` does not contain a valid message.
    pub fn read<const N: usize>(buf: &mut FixedBuf<N>) -> Result<Self, DnsError> {
        let header = DnsMessageHeader::read(buf)?;
        let mut questions = Vec::with_capacity(header.question_count as usize);
        for _ in 0..header.question_count {
            let question = DnsQuestion::read(buf)?;
            questions.push(question);
        }
        let mut answers = Vec::with_capacity(header.answer_count as usize);
        for _ in 0..header.answer_count {
            let record = DnsRecord::read(buf)?;
            answers.push(record);
        }
        let mut name_servers = Vec::with_capacity(header.name_server_count as usize);
        for _ in 0..header.name_server_count {
            let record = DnsRecord::read(buf)?;
            name_servers.push(record);
        }
        let mut additional = Vec::with_capacity(header.additional_count as usize);
        for _ in 0..header.additional_count {
            #[allow(clippy::single_match)]
            match DnsRecord::read(buf) {
                Ok(record) => additional.push(record),
                // Ignore invalid additional records.
                Err(_) => {}
            }
        }
        Ok(Self {
            header,
            questions,
            answers,
            name_servers,
            additional,
        })
    }

    /// # Errors
    /// Returns an error when `buf` fills up.
    pub fn write<const N: usize>(&self, out: &mut FixedBuf<N>) -> Result<(), DnsError> {
        self.header.write(out)?;
        for question in &self.questions {
            question.write(out)?;
        }
        for record in self
            .answers
            .iter()
            .chain(self.name_servers.iter())
            .chain(self.additional.iter())
        {
            record.write(out)?;
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error when there are more than 65,536 questions.
    pub fn answer_response<'x>(
        &self,
        answers: impl Iterator<Item = &'x DnsRecord>,
    ) -> Result<Self, DnsError> {
        let answers: Vec<DnsRecord> = answers.cloned().collect();
        let answer_count = u16::try_from(answers.len()).map_err(|_| DnsError::TooManyAnswers)?;
        Ok(Self {
            header: DnsMessageHeader {
                id: self.header.id,
                is_response: true,
                op_code: self.header.op_code,
                authoritative_answer: true,
                truncated: false,
                recursion_desired: self.header.recursion_desired,
                recursion_available: false,
                response_code: DnsResponseCode::NoError,
                question_count: self.question_count()?,
                answer_count,
                name_server_count: 0,
                additional_count: 0,
            },
            questions: self.questions.clone(),
            answers,
            name_servers: Vec::new(),
            additional: Vec::new(),
        })
    }

    /// # Errors
    /// Returns an error when there are more than 65,536 questions.
    pub fn error_response(&self, response_code: DnsResponseCode) -> Result<Self, DnsError> {
        Ok(Self {
            header: DnsMessageHeader {
                id: self.header.id,
                is_response: true,
                op_code: self.header.op_code,
                authoritative_answer: true,
                truncated: false,
                recursion_desired: self.header.recursion_desired,
                recursion_available: false,
                response_code,
                question_count: self.question_count()?,
                answer_count: 0,
                name_server_count: 0,
                additional_count: 0,
            },
            questions: self.questions.clone(),
            answers: Vec::new(),
            name_servers: Vec::new(),
            additional: Vec::new(),
        })
    }
}
